#include <v8.h>
#include <node.h>
#include <string.h>
#include <unistd.h>
#include <node_object_wrap.h>
#include <kstat.h>
#include <errno.h>
#include <string>
#include <vector>
#include <sys/varargs.h>
#include <sys/sysinfo.h>

using namespace v8;
using std::string;
using std::vector;

class KStatReader : node::ObjectWrap {
public:
	static void Initialize(Handle<Object> target);

protected:
	static Persistent<FunctionTemplate> templ;

	typedef struct {
		int data_type;
		uint32_t value_ui32;
		uint64_t value_ui64;
		string value_str;
	} write_value_t;

	KStatReader(string *module, string *classname,
	    string *name, int instance);
	Handle<Value> error(const char *fmt, ...);
	Handle<Value> read(kstat_t *);
	kstat_named_t* write(char *, write_value_t *);
	int update();
	~KStatReader();

	static Handle<Value> New(const Arguments& args);
	static Handle<Value> Read(const Arguments& args);
	static Handle<Value> Write(const Arguments& args);
	static Handle<Value> Update(const Arguments& args);
	static void EIO_Write(eio_req *req);
	static int EIO_AfterWrite(eio_req *req);
	static Handle<Value> WriteAsync(const Arguments& args);

	typedef struct {
		KStatReader *k;
		Persistent<Function> cb;
		string name;
		write_value_t val;
		string error;
	} write_baton_t;

private:
	static string *stringMember(Local<Value>, char *, char *);
	static int64_t intMember(Local<Value>, char *, int64_t);
	Handle<Object> data_named(kstat_t *);
	Handle<Object> data_io(kstat_t *);
	Handle<Object> data_raw(kstat_t *);

	string *ksr_module;
	string *ksr_class;
	string *ksr_name;
	int ksr_instance;
	kid_t ksr_kid;
	kstat_ctl_t *ksr_ctl;
	vector<kstat_t *> ksr_kstats;
};

Persistent<FunctionTemplate> KStatReader::templ;

KStatReader::KStatReader(string *module, string *classname,
    string *name, int instance)
    : node::ObjectWrap(), ksr_module(module), ksr_class(classname),
    ksr_name(name), ksr_instance(instance), ksr_kid(-1)
{
	if ((ksr_ctl = kstat_open()) == NULL)
		throw "could not open kstat";
};

KStatReader::~KStatReader()
{
	delete ksr_module;
	delete ksr_class;
	delete ksr_name;
	kstat_close(ksr_ctl);
}

int
KStatReader::update()
{
	kstat_t *ksp;
	kid_t kid;

	if ((kid = kstat_chain_update(ksr_ctl)) == 0 && ksr_kid != -1)
		return (0);

	if (kid == -1)
		return (-1);

	ksr_kid = kid;
	ksr_kstats.clear();

	for (ksp = ksr_ctl->kc_chain; ksp != NULL; ksp = ksp->ks_next) {
		if (!ksr_module->empty() &&
		    ksr_module->compare(ksp->ks_module) != 0)
			continue;

		if (!ksr_class->empty() &&
		    ksr_class->compare(ksp->ks_class) != 0)
			continue;

		if (!ksr_name->empty() && ksr_name->compare(ksp->ks_name) != 0)
			continue;

		if (ksr_instance != -1 && ksp->ks_instance != ksr_instance)
			continue;

		ksr_kstats.push_back(ksp);
	}

	return (0);
}

void
KStatReader::Initialize(Handle<Object> target)
{
	HandleScope scope;

	Local<FunctionTemplate> k = FunctionTemplate::New(KStatReader::New);

	templ = Persistent<FunctionTemplate>::New(k);
	templ->InstanceTemplate()->SetInternalFieldCount(1);
	templ->SetClassName(String::NewSymbol("Reader"));

	NODE_SET_PROTOTYPE_METHOD(templ, "read", KStatReader::Read);
	NODE_SET_PROTOTYPE_METHOD(templ, "write", KStatReader::Write);
	NODE_SET_PROTOTYPE_METHOD(templ, "writeAsync", KStatReader::WriteAsync);

	target->Set(String::NewSymbol("Reader"), templ->GetFunction());
}

string *
KStatReader::stringMember(Local<Value> value, char *member, char *deflt)
{
	if (!value->IsObject())
		return (new string (deflt));

	Local<Object> o = Local<Object>::Cast(value);
	Local<Value> v = o->Get(String::New(member));

	if (!v->IsString())
		return (new string (deflt));

	String::AsciiValue val(v);
	return (new string(*val));
}

int64_t
KStatReader::intMember(Local<Value> value, char *member, int64_t deflt)
{
	int64_t rval = deflt;

	if (!value->IsObject())
		return (rval);

	Local<Object> o = Local<Object>::Cast(value);
	value = o->Get(String::New(member));

	if (!value->IsNumber())
		return (rval);

	Local<Integer> i = Local<Integer>::Cast(value);

	return (i->Value());
}

Handle<Value>
KStatReader::New(const Arguments& args)
{
	HandleScope scope;

	KStatReader *k = new KStatReader(stringMember(args[0], "module", ""),
	    stringMember(args[0], "class", ""),
	    stringMember(args[0], "name", ""),
	    intMember(args[0], "instance", -1));

	k->Wrap(args.Holder());

	return (args.This());
}

Handle<Value>
KStatReader::error(const char *fmt, ...)
{
	char buf[1024], buf2[1024];
	char *err = buf;
	va_list ap;

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);

	if (buf[strlen(buf) - 1] != '\n') {
		/*
		 * If our error doesn't end in a new-line, we'll append the
		 * strerror of errno.
		 */
		(void) snprintf(err = buf2, sizeof (buf2),
		    "%s: %s", buf, strerror(errno));
	} else {
		buf[strlen(buf) - 1] = '\0';
	}

	return (ThrowException(Exception::Error(String::New(err))));
}

Handle<Object>
KStatReader::data_named(kstat_t *ksp)
{
	Handle<Object> data = Object::New();
	kstat_named_t *nm = KSTAT_NAMED_PTR(ksp);
	int i;

	assert(ksp->ks_type == KSTAT_TYPE_NAMED);

	for (i = 0; i < ksp->ks_ndata; i++, nm++) {
		Handle<Value> val;

		switch (nm->data_type) {
		case KSTAT_DATA_CHAR:
			/* must protect string ending */
			nm->value.c[15] = '\0';
			val = String::New(nm->value.c);
			break;

		case KSTAT_DATA_INT32:
			val = Number::New(nm->value.i32);
			break;

		case KSTAT_DATA_UINT32:
			val = Number::New(nm->value.ui32);
			break;

		case KSTAT_DATA_INT64:
			val = Number::New(nm->value.i64);
			break;

		case KSTAT_DATA_UINT64:
			val = Number::New(nm->value.ui64);
			break;

		case KSTAT_DATA_STRING:
			/* actually STR_PTR can be NULL and this is normal */
			val = String::New(KSTAT_NAMED_STR_PTR(nm) ?
			    KSTAT_NAMED_STR_PTR(nm) : "");
			break;

		default:
			throw (error("unrecognized data type %d for member "
			    "\"%s\" in instance %d of stat \"%s\" (module "
			    "\"%s\", class \"%s\")\n", nm->data_type,
			    nm->name, ksp->ks_instance, ksp->ks_name,
			    ksp->ks_module, ksp->ks_class));
		}

		data->Set(String::New(nm->name), val);
	}

	return (data);
}

Handle<Object>
KStatReader::data_io(kstat_t *ksp)
{
	Handle<Object> data = Object::New();
	kstat_io_t *io = KSTAT_IO_PTR(ksp);

	assert(ksp->ks_type == KSTAT_TYPE_IO);

	data->Set(String::New("nread"), Number::New(io->nread));
	data->Set(String::New("nwritten"), Number::New(io->nwritten));
	data->Set(String::New("reads"), Integer::New(io->reads));
	data->Set(String::New("writes"), Integer::New(io->writes));

	data->Set(String::New("wtime"), Number::New(io->wtime));
	data->Set(String::New("wlentime"), Number::New(io->wlentime));
	data->Set(String::New("wlastupdate"), Number::New(io->wlastupdate));

	data->Set(String::New("rtime"), Number::New(io->rtime));
	data->Set(String::New("rlentime"), Number::New(io->rlentime));
	data->Set(String::New("rlastupdate"), Number::New(io->rlastupdate));

	data->Set(String::New("wcnt"), Integer::New(io->wcnt));
	data->Set(String::New("rcnt"), Integer::New(io->rcnt));

	return (data);
}

Handle<Object>
KStatReader::data_raw(kstat_t *ksp)
{
	vminfo_t *vminfo;
	cpu_stat_t *stat;
	cpu_sysinfo_t *sysinfo;
	static char buf[10];

	Handle<Object> data = Object::New();

	assert(ksp->ks_type == KSTAT_TYPE_RAW);

	/* Get just some interesting data */
	if (strncmp(ksp->ks_module, "unix", 4) == 0) {
		if (strncmp(ksp->ks_name, "vminfo", 6) == 0) {
			vminfo = (vminfo_t *) (ksp->ks_data);

			data->Set(String::New("freemem"),
			    Number::New(vminfo->freemem));
			data->Set(String::New("swap_resv"),
			    Number::New(vminfo->swap_resv));
			data->Set(String::New("swap_alloc"),
			    Number::New(vminfo->swap_alloc));
			data->Set(String::New("swap_avail"),
			    Number::New(vminfo->swap_avail));
			data->Set(String::New("swap_free"),
			    Number::New(vminfo->swap_free));
			data->Set(String::New("updates"),
			    Number::New(vminfo->updates));
		}
	}

	if (strcmp(ksp->ks_module, "cpu_stat") == 0) {
		(void) snprintf(buf, sizeof (buf), "cpu_stat%d",
		    ksp->ks_instance);
		if (strncmp(ksp->ks_name, buf, sizeof (buf)) == 0) {
			stat = (cpu_stat_t *) (ksp->ks_data);
			sysinfo = &stat->cpu_sysinfo;
			data->Set(String::New("idle"),
			    Number::New(sysinfo->cpu[CPU_IDLE]));
			data->Set(String::New("user"), 
			    Number::New(sysinfo->cpu[CPU_USER]));
			data->Set(String::New("kernel"),
			    Number::New(sysinfo->cpu[CPU_KERNEL]));
			data->Set(String::New("wait"),
			    Number::New(sysinfo->cpu[CPU_WAIT]));
			data->Set(String::New("wait_io"),
			    Number::New(sysinfo->cpu[W_IO]));
			data->Set(String::New("wait_swap"),
			    Number::New(sysinfo->cpu[W_SWAP]));
			data->Set(String::New("wait_pio"),
			    Number::New(sysinfo->cpu[W_PIO]));
		}
	}

       return (data);
}

Handle<Value>
KStatReader::read(kstat_t *ksp)
{
	Handle<Object> rval = Object::New();
	Handle<Object> data;

	rval->Set(String::New("class"), String::New(ksp->ks_class));
	rval->Set(String::New("module"), String::New(ksp->ks_module));
	rval->Set(String::New("name"), String::New(ksp->ks_name));
	rval->Set(String::New("instance"), Integer::New(ksp->ks_instance));

	if (kstat_read(ksr_ctl, ksp, NULL) == -1) {
		/*
		 * It is deeply annoying, but some kstats can return errors
		 * under otherwise routine conditions.  (ACPI is one
		 * offender; there are surely others.)  To prevent these
		 * fouled kstats from completely ruining our day, we assign
		 * an "error" member to the return value that consists of
		 * the strerror().
		 */
		rval->Set(String::New("error"), String::New(strerror(errno)));
		return (rval);
	}

	rval->Set(String::New("instance"), Integer::New(ksp->ks_instance));
	rval->Set(String::New("snaptime"), Number::New(ksp->ks_snaptime));
	rval->Set(String::New("crtime"), Number::New(ksp->ks_crtime));

	if (ksp->ks_type == KSTAT_TYPE_NAMED) {
		data = data_named(ksp);
	} else if (ksp->ks_type == KSTAT_TYPE_IO) {
		data = data_io(ksp);
	} else if (ksp->ks_type == KSTAT_TYPE_RAW) {
		data = data_raw(ksp);
	} else {
		return (rval);
	}

	rval->Set(String::New("data"), data);

	return (rval);
}

Handle<Value>
KStatReader::Read(const Arguments& args)
{
	KStatReader *k = ObjectWrap::Unwrap<KStatReader>(args.Holder());
	Handle<Object> rval = Object::New();
	HandleScope scope;
	int i;

	if (k->update() == -1)
		return (k->error("failed to update kstat chain"));

	rval = Array::New(k->ksr_kstats.size());

	try {
		for (i = 0; i < k->ksr_kstats.size(); i++)
			rval->Set(i, k->read(k->ksr_kstats[i]));
	} catch (Handle<Value> err) {
		return (err);
	}

	return (rval);
}

kstat_named_t*
KStatReader::write(char *name, write_value_t *val)
{
	kstat_t *ksp;
	kstat_named_t *knp;

	ksp = kstat_lookup(ksr_ctl, (char*)ksr_module->c_str(), ksr_instance,
			   (char*)ksr_name->c_str());
	if (!ksp)
		return NULL;

	if (kstat_read(ksr_ctl, ksp, NULL) == -1)
		return NULL;

	knp = (kstat_named_t *) kstat_data_lookup(ksp, name);
	if (!knp)
		return NULL;

	if (val->data_type == KSTAT_DATA_UINT32) {
		knp->value.ui32 = val->value_ui32;
	} else if (val->data_type == KSTAT_DATA_UINT64) {
		knp->value.ui64 = val->value_ui64;
	} else if (val->data_type == KSTAT_DATA_STRING) {
		KSTAT_NAMED_STR_PTR(knp) = (char*)KSTAT_NAMED_PTR(ksp) +
		    ksp->ks_ndata * sizeof(kstat_named_t);
		KSTAT_NAMED_STR_BUFLEN(knp) = val->value_str.length() + 1;
		strcpy(KSTAT_NAMED_STR_PTR(knp),
		    (char *)val->value_str.c_str());
	}

	if (kstat_write(ksr_ctl, ksp, NULL) == -1) {
		return NULL;
	}

	return knp;
}

Handle<Value>
KStatReader::Write(const Arguments& args)
{
	KStatReader *k = ObjectWrap::Unwrap<KStatReader>(args.Holder());
	Handle<Object> rval = Object::New();
	HandleScope scope;
	kstat_named_t *knp;

	if (args.Length() < 2 || !args[0]->IsString())
		return (k->error("first argument must be string"));
	String::Utf8Value name(args[0]->ToString());

	if (args.Length() < 2)
		return (k->error("second argument is not specified"));

	write_value_t val;
	Local<Value> value = args[1];
	if (value->IsUint32()) {
		val.data_type = KSTAT_DATA_UINT32;
		val.value_ui32 = value->Uint32Value();
	} else if (value->IsNumber()) {
		val.data_type = KSTAT_DATA_UINT64;
		val.value_ui64 = value->NumberValue();
	} else if (value->IsString()) {
		String::Utf8Value str(value->ToString());
		val.data_type = KSTAT_DATA_STRING;
		val.value_str = *str;
	}
	knp = k->write(*name, &val);
	if (knp == NULL)
		return (k->error("can't write kstat"));

	return (rval);
}

void
KStatReader::EIO_Write(eio_req *req)
{
	write_baton_t *baton = static_cast<write_baton_t *>(req->data);
	kstat_named_t *knp;

	knp = baton->k->write((char*)baton->name.c_str(), &baton->val);
	if (knp == NULL)
		baton->error = strerror(errno);
}

int
KStatReader::EIO_AfterWrite(eio_req *req)
{
	HandleScope scope;
	write_baton_t *baton = static_cast<write_baton_t *>(req->data);
	ev_unref(EV_DEFAULT_UC);
	baton->k->Unref();
	Local<Value> argv[1];

	if (!baton->error.empty()) {
		Local<Value> err =
		    Exception::Error(String::New(baton->error.c_str()));
		argv[0] = err;
	} else {
		argv[0] = Local<Value>::New(Null());
	}

	TryCatch try_catch;
	baton->cb->Call(Context::GetCurrent()->Global(), 1, argv);
	if (try_catch.HasCaught()) {
		node::FatalException(try_catch);
	}

	baton->cb.Dispose();
	delete baton;
	return 0;
}

Handle<Value>
KStatReader::WriteAsync(const Arguments& args)
{
	KStatReader *k = ObjectWrap::Unwrap<KStatReader>(args.Holder());
	Handle<Object> rval = Object::New();
	HandleScope scope;

	if (args.Length() < 3)
		return (k->error("expecting 3 arguments"));

	if (!args[0]->IsString())
		return (k->error("first argument must be string"));
	String::Utf8Value name(args[0]->ToString());
	Local<Value> value = args[1];

	if (!args[2]->IsFunction())
		return (k->error("third argument is not function"));
	Local<Function> cb = Local<Function>::Cast(args[2]);

	write_baton_t *baton = new write_baton_t();
	baton->k = k;
	baton->cb = Persistent<Function>::New(cb);
	baton->name = *name;

	if (value->IsUint32()) {
		baton->val.data_type = KSTAT_DATA_UINT32;
		baton->val.value_ui32 = value->Uint32Value();
	} else if (value->IsNumber()) {
		baton->val.data_type = KSTAT_DATA_UINT64;
		baton->val.value_ui64 = value->NumberValue();
	} else if (value->IsString()) {
		String::Utf8Value str(value->ToString());
		baton->val.data_type = KSTAT_DATA_STRING;
		baton->val.value_str = *str;
	}

	k->Ref();

	eio_custom(EIO_Write, EIO_PRI_DEFAULT, EIO_AfterWrite, baton);
	ev_ref(EV_DEFAULT_UC);

	return (rval);
}

extern "C" void
init (Handle<Object> target)
{
	KStatReader::Initialize(target);
}
