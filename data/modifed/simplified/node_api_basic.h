#define NAPI_EXTERN __attribute__((visibility("default")))

// JSVM API types are all opaque pointers for ABI stability
// typedef undefined structs instead of void* for compile time type safety
typedef void* napi_env;
typedef void* napi_value;
typedef void* napi_ref;
typedef void* napi_handle_scope;
typedef void* napi_escapable_handle_scope;
typedef void* napi_callback_info;
typedef void* napi_deferred;

typedef enum {
  napi_ok,
  napi_invalid_arg,
  napi_object_expected,
  napi_string_expected,
  napi_name_expected,
  napi_function_expected,
  napi_number_expected,
  napi_boolean_expected,
  napi_array_expected,
  napi_generic_failure,
  napi_pending_exception,
  napi_cancelled,
  napi_escape_called_twice,
  napi_handle_scope_mismatch,
  napi_callback_scope_mismatch,
  napi_queue_full,
  napi_closing,
  napi_bigint_expected,
  napi_date_expected,
  napi_arraybuffer_expected,
  napi_detachable_arraybuffer_expected,
  napi_would_deadlock,  // unused
  napi_create_ark_runtime_too_many_envs = 22,
  napi_create_ark_runtime_only_one_env_per_thread = 23,
  napi_destroy_ark_runtime_env_not_exist = 24
} napi_status;

typedef napi_value (*napi_callback)(napi_env env,
                                    napi_callback_info info);

typedef enum {
  napi_default = 0,
  napi_writable = 1 << 0,
  napi_enumerable = 1 << 1,
  napi_configurable = 1 << 2,

  // Used with napi_define_class to distinguish static properties
  // from instance properties. Ignored by napi_define_properties.
  napi_static = 1 << 10,

// #if NAPI_VERSION >= 8
  // Default for class methods.
  napi_default_method = napi_writable | napi_configurable,

  // Default for object properties, like in JS obj[prop].
  napi_default_jsproperty = napi_writable |
                            napi_enumerable |
                            napi_configurable,
// #endif  // NAPI_VERSION >= 8
} napi_property_attributes;

typedef struct {
  // One of utf8name or name should be NULL.
  const char* utf8name;
  napi_value name;

  napi_callback method;
  napi_callback getter;
  napi_callback setter;
  napi_value value;

  napi_property_attributes attributes;
  void* data;
} napi_property_descriptor;



typedef napi_value (*napi_addon_register_func)(napi_env env,
                                               napi_value exports);


typedef struct napi_module {
  int nm_version;
  unsigned int nm_flags;
  const char* nm_filename;
  napi_addon_register_func nm_register_func;
  const char* nm_modname;
  void* nm_priv;
  void* reserved[4];
} napi_module;

NAPI_EXTERN void napi_module_register(napi_module* mod);

NAPI_EXTERN napi_status
napi_define_properties(napi_env env,
                       napi_value object,
                       unsigned long property_count, // size_t
                       const napi_property_descriptor* properties);
