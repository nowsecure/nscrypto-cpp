%module nscrypto
%{
#include "nscrypto.h"
%}

%include "std_string.i"

#if defined(SWIG_JAVASCRIPT_V8)

%begin %{

// Workaround for building for Node.js 0.12.0
#ifndef SWIG_V8_VERSION
    #include <node_version.h>
    #if NODE_MAJOR_VERSION == 0 && NODE_MINOR_VERSION == 12 && NODE_PATCH_VERSION == 0
        #define SWIG_V8_VERSION 0x032873
    #endif
#endif

%}

%header %{

#include <node_buffer.h>

static bool _is_buffer(const v8::Handle<v8::Value> v) {
    v8::String::Utf8Value t(v->ToObject()->GetConstructorName());
    std::string name(*t);
    return name == "Buffer" || name == "NativeBuffer" || name == "SlowBuffer";
}

static v8::Local<v8::Object> _bufferize(const std::string& value) {
    v8::Local<v8::Object> global_obj = SWIGV8_CURRENT_CONTEXT()->Global();
    v8::Local<v8::Function> buffer_ctor = v8::Local<v8::Function>::Cast(global_obj->Get(SWIGV8_SYMBOL_NEW("Buffer")));
    v8::Handle<v8::Value> ctor_args[1] = { SWIGV8_INTEGER_NEW(value.size()) };
    v8::Local<v8::Object> buffer = buffer_ctor->NewInstance(1, ctor_args);
    memmove(node::Buffer::Data(buffer), value.data(), value.size());
    return buffer;
}

static std::string _stringinize(const v8::Handle<v8::Value> v) {
    if (_is_buffer(v)) {
        return std::string(node::Buffer::Data(v), node::Buffer::Length(v));
    }

    return std::string();
}

%}

%typemap(out) std::string %{
    $result = _bufferize($1);
%}

%typemap(out) keypair_t {
    auto t = SWIGV8_OBJECT_NEW();
    t->Set(SWIGV8_SYMBOL_NEW("private"), _bufferize(std::get<0>($1)));
    t->Set(SWIGV8_SYMBOL_NEW("public"), _bufferize(std::get<1>($1)));
    $result = t;
}

%typemap(out) ecdh_encrypted_t {
    auto t = SWIGV8_OBJECT_NEW();
    t->Set(SWIGV8_SYMBOL_NEW("enc"), _bufferize(std::get<0>($1) + std::get<1>($1)));
    t->Set(SWIGV8_SYMBOL_NEW("eph"), _bufferize(std::get<2>($1)));
    $result = t;
}

%typemap(in) const std::string& s_priv (std::string temp),
             const std::string& r_priv (std::string temp),
             const std::string& s_pub (std::string temp),
             const std::string& r_pub (std::string temp),
             const std::string& message (std::string temp) %{
   temp = _stringinize($input);
   $1 = &temp;
%}

%typemap(freearg) const std::string& s_priv, const std::string& r_priv,
                  const std::string& s_pub, const std::string& r_pub,
                  const std::string& message %{
%}

%typemap(in) const ecdh_encrypted_t& (ecdh_encrypted_t temp) {
    auto t = $input->ToObject();
    std::string enc(_stringinize(t->Get(SWIGV8_SYMBOL_NEW("enc")))), eph(_stringinize(t->Get(SWIGV8_SYMBOL_NEW("eph"))));
    if (enc.size() > 16 && !eph.empty()) {
        temp = ecdh_encrypted_t(enc.substr(0, enc.size() - 16), enc.substr(enc.size() - 16), eph);
    } else {
        temp = ecdh_encrypted_t(std::string(), std::string(), std::string());
    }

    $1 = &temp;
}

#else
    #warning No typemaps declared
#endif

keypair_t ec_keypair();

ecdh_encrypted_t ecdh_client_encrypt(const std::string& s_priv, const std::string& r_pub,
                                     const std::string& s_id, const std::string& r_id,
                                     const std::string& message);

ecdh_encrypted_t ecdh_server_encrypt(const std::string& s_priv, const std::string& r_pub,
                                     const std::string& s_id, const std::string& r_id,
                                     const std::string& message);

std::string ecdh_server_decrypt(const std::string& r_priv, const std::string& s_pub,
                                const std::string& s_id, const std::string& r_id,
                                const ecdh_encrypted_t& encrypted);

std::string ecdh_client_decrypt(const std::string& r_priv, const std::string& s_pub,
                                const std::string& s_id, const std::string& r_id,
                                const ecdh_encrypted_t& encrypted);
