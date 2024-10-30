/*************************************************************************** +
 * 
 *  some intergers
 * 
****************************************************************************/

#define _Int64 long
#define _Addr long

typedef unsigned _Int64 uint64_t;
typedef signed _Int64   int64_t;
typedef unsigned int uint32_t;
typedef signed int int32_t;
typedef unsigned _Addr size_t;
typedef unsigned short  uint16_t;

typedef char16_t uint16_t;

/*************************************************************************** +
 * 
 *  common.h
 * 
****************************************************************************/

typedef enum {
    napi_qos_background = 0,
    napi_qos_utility = 1,
    napi_qos_default = 2,
    napi_qos_user_initiated = 3,
} napi_qos_t;

/**
 * @brief Indicates the running mode of the native event loop in an asynchronous native thread.
 *
 * @since 12
 */
typedef enum {
    /**
     * In this mode, the current asynchronous thread will be blocked and events of native event loop will
     * be processed.
     */
    napi_event_mode_default = 0,

    /**
     * In this mode, the current asynchronous thread will not be blocked. If there are events in the event loop,
     * only one event will be processed and then the event loop will stop. If there are no events in the loop,
     * the event loop will stop immediately.
     */
    napi_event_mode_nowait = 1,
} napi_event_mode;

/**
 * @brief Indicates the priority of a task dispatched from native thread to ArkTS thread.
 *
 * @since 12
 */
typedef enum {
    /**
     * The immediate priority tasks should be promptly processed whenever feasible.
     */
    napi_priority_immediate = 0,
    /**
     * The high priority tasks, as sorted by their handle time, should be prioritized over tasks with low priority.
     */
    napi_priority_high = 1,
    /**
     * The low priority tasks, as sorted by their handle time, should be processed before idle priority tasks.
     */
    napi_priority_low = 2,
    /**
     * The idle priority tasks should be processed immediately only if there are no other priority tasks.
     */
    napi_priority_idle = 3,
} napi_task_priority;

/*************************************************************************** +
 * 
 *  js_native_api_types.h
 * 
****************************************************************************/

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

typedef enum {
  // ES6 types (corresponds to typeof)
  napi_undefined,
  napi_null,
  napi_boolean,
  napi_number,
  napi_string,
  napi_symbol,
  napi_object,
  napi_function,
  napi_external,
  napi_bigint,
} napi_valuetype;

typedef enum {
  napi_int8_array,
  napi_uint8_array,
  napi_uint8_clamped_array,
  napi_int16_array,
  napi_uint16_array,
  napi_int32_array,
  napi_uint32_array,
  napi_float32_array,
  napi_float64_array,
  napi_bigint64_array,
  napi_biguint64_array,
} napi_typedarray_type;

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
typedef void (*napi_finalize)(napi_env env,
                              void* finalize_data,
                              void* finalize_hint);

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

typedef struct {
  const char* error_message;
  void* engine_reserved;
  uint32_t engine_error_code;
  napi_status error_code;
} napi_extended_error_info;

typedef enum {
  napi_key_include_prototypes,
  napi_key_own_only
} napi_key_collection_mode;

typedef enum {
  napi_key_all_properties = 0,
  napi_key_writable = 1,
  napi_key_enumerable = 1 << 1,
  napi_key_configurable = 1 << 2,
  napi_key_skip_strings = 1 << 3,
  napi_key_skip_symbols = 1 << 4
} napi_key_filter;

typedef enum {
  napi_key_keep_numbers,
  napi_key_numbers_to_strings
} napi_key_conversion;

typedef struct {
  uint64_t lower;
  uint64_t upper;
} napi_type_tag;

/*************************************************************************** +
 * 
 *  node_api_types.h
 * 
****************************************************************************/

typedef void* napi_callback_scope;
typedef void* napi_async_context;
typedef void* napi_async_work;

typedef void* napi_threadsafe_function;

typedef enum {
  napi_tsfn_release,
  napi_tsfn_abort
} napi_threadsafe_function_release_mode;

typedef enum {
  napi_tsfn_nonblocking,
  napi_tsfn_blocking
} napi_threadsafe_function_call_mode;

typedef void (*napi_async_execute_callback)(napi_env env,
                                            void* data);
typedef void (*napi_async_complete_callback)(napi_env env,
                                             napi_status status,
                                             void* data);

typedef void (*napi_threadsafe_function_call_js)(napi_env env,
                                                 napi_value js_callback,
                                                 void* context,
                                                 void* data);

typedef struct {
  uint32_t major;
  uint32_t minor;
  uint32_t patch;
  const char* release;
} napi_node_version;                                          

typedef void* napi_async_cleanup_hook_handle;
typedef void (*napi_async_cleanup_hook)(napi_async_cleanup_hook_handle handle,
                                        void* data);

/*************************************************************************** +
 * 
 *  js_native_api.h
 * 
****************************************************************************/

// #ifndef NAPI_EXTERN
//   #ifdef _WIN32
    #define NAPI_EXTERN __declspec(dllexport)
//   #elif defined(__wasm32__)
//     #define NAPI_EXTERN __attribute__((visibility("default")))                \
//                         __attribute__((__import_module__("napi")))
//   #else
//     #define NAPI_EXTERN __attribute__((visibility("default")))
//   #endif
// #endif


NAPI_EXTERN napi_status
napi_get_last_error_info(napi_env env,
                         const napi_extended_error_info** result);

// Getters for defined singletons
NAPI_EXTERN napi_status napi_get_undefined(napi_env env, napi_value* result);
NAPI_EXTERN napi_status napi_get_null(napi_env env, napi_value* result);
NAPI_EXTERN napi_status napi_get_global(napi_env env, napi_value* result);
NAPI_EXTERN napi_status napi_get_boolean(napi_env env,
                                         bool value,
                                         napi_value* result);

// Methods to create Primitive types/Objects
NAPI_EXTERN napi_status napi_create_object(napi_env env, napi_value* result);
NAPI_EXTERN napi_status napi_create_array(napi_env env, napi_value* result);
NAPI_EXTERN napi_status napi_create_array_with_length(napi_env env,
                                                      size_t length,
                                                      napi_value* result);
NAPI_EXTERN napi_status napi_create_double(napi_env env,
                                           double value,
                                           napi_value* result);
NAPI_EXTERN napi_status napi_create_int32(napi_env env,
                                          int32_t value,
                                          napi_value* result);
NAPI_EXTERN napi_status napi_create_uint32(napi_env env,
                                           uint32_t value,
                                           napi_value* result);
NAPI_EXTERN napi_status napi_create_int64(napi_env env,
                                          int64_t value,
                                          napi_value* result);
NAPI_EXTERN napi_status napi_create_string_latin1(napi_env env,
                                                  const char* str,
                                                  size_t length,
                                                  napi_value* result);
NAPI_EXTERN napi_status napi_create_string_utf8(napi_env env,
                                                const char* str,
                                                size_t length,
                                                napi_value* result);
NAPI_EXTERN napi_status napi_create_string_utf16(napi_env env,
                                                 const char16_t* str,
                                                 size_t length,
                                                 napi_value* result);
NAPI_EXTERN napi_status napi_create_symbol(napi_env env,
                                           napi_value description,
                                           napi_value* result);
NAPI_EXTERN napi_status napi_create_function(napi_env env,
                                             const char* utf8name,
                                             size_t length,
                                             napi_callback cb,
                                             void* data,
                                             napi_value* result);
NAPI_EXTERN napi_status napi_create_error(napi_env env,
                                          napi_value code,
                                          napi_value msg,
                                          napi_value* result);
NAPI_EXTERN napi_status napi_create_type_error(napi_env env,
                                               napi_value code,
                                               napi_value msg,
                                               napi_value* result);
NAPI_EXTERN napi_status napi_create_range_error(napi_env env,
                                                napi_value code,
                                                napi_value msg,
                                                napi_value* result);

// Methods to get the native napi_value from Primitive type
NAPI_EXTERN napi_status napi_typeof(napi_env env,
                                    napi_value value,
                                    napi_valuetype* result);
NAPI_EXTERN napi_status napi_get_value_double(napi_env env,
                                              napi_value value,
                                              double* result);
NAPI_EXTERN napi_status napi_get_value_int32(napi_env env,
                                             napi_value value,
                                             int32_t* result);
NAPI_EXTERN napi_status napi_get_value_uint32(napi_env env,
                                              napi_value value,
                                              uint32_t* result);
NAPI_EXTERN napi_status napi_get_value_int64(napi_env env,
                                             napi_value value,
                                             int64_t* result);
NAPI_EXTERN napi_status napi_get_value_bool(napi_env env,
                                            napi_value value,
                                            bool* result);

// Copies LATIN-1 encoded bytes from a string into a buffer.
NAPI_EXTERN napi_status napi_get_value_string_latin1(napi_env env,
                                                     napi_value value,
                                                     char* buf,
                                                     size_t bufsize,
                                                     size_t* result);

// Copies UTF-8 encoded bytes from a string into a buffer.
NAPI_EXTERN napi_status napi_get_value_string_utf8(napi_env env,
                                                   napi_value value,
                                                   char* buf,
                                                   size_t bufsize,
                                                   size_t* result);

// Copies UTF-16 encoded bytes from a string into a buffer.
NAPI_EXTERN napi_status napi_get_value_string_utf16(napi_env env,
                                                    napi_value value,
                                                    char16_t* buf,
                                                    size_t bufsize,
                                                    size_t* result);

// Methods to coerce values
// These APIs may execute user scripts
NAPI_EXTERN napi_status napi_coerce_to_bool(napi_env env,
                                            napi_value value,
                                            napi_value* result);
NAPI_EXTERN napi_status napi_coerce_to_number(napi_env env,
                                              napi_value value,
                                              napi_value* result);
NAPI_EXTERN napi_status napi_coerce_to_object(napi_env env,
                                              napi_value value,
                                              napi_value* result);
NAPI_EXTERN napi_status napi_coerce_to_string(napi_env env,
                                              napi_value value,
                                              napi_value* result);

// Methods to work with Objects
NAPI_EXTERN napi_status napi_get_prototype(napi_env env,
                                           napi_value object,
                                           napi_value* result);
NAPI_EXTERN napi_status napi_get_property_names(napi_env env,
                                                napi_value object,
                                                napi_value* result);
NAPI_EXTERN napi_status napi_set_property(napi_env env,
                                          napi_value object,
                                          napi_value key,
                                          napi_value value);
NAPI_EXTERN napi_status napi_has_property(napi_env env,
                                          napi_value object,
                                          napi_value key,
                                          bool* result);
NAPI_EXTERN napi_status napi_get_property(napi_env env,
                                          napi_value object,
                                          napi_value key,
                                          napi_value* result);
NAPI_EXTERN napi_status napi_delete_property(napi_env env,
                                             napi_value object,
                                             napi_value key,
                                             bool* result);
NAPI_EXTERN napi_status napi_has_own_property(napi_env env,
                                              napi_value object,
                                              napi_value key,
                                              bool* result);
NAPI_EXTERN napi_status napi_set_named_property(napi_env env,
                                          napi_value object,
                                          const char* utf8name,
                                          napi_value value);
NAPI_EXTERN napi_status napi_has_named_property(napi_env env,
                                          napi_value object,
                                          const char* utf8name,
                                          bool* result);
NAPI_EXTERN napi_status napi_get_named_property(napi_env env,
                                          napi_value object,
                                          const char* utf8name,
                                          napi_value* result);
NAPI_EXTERN napi_status napi_set_element(napi_env env,
                                         napi_value object,
                                         uint32_t index,
                                         napi_value value);
NAPI_EXTERN napi_status napi_has_element(napi_env env,
                                         napi_value object,
                                         uint32_t index,
                                         bool* result);
NAPI_EXTERN napi_status napi_get_element(napi_env env,
                                         napi_value object,
                                         uint32_t index,
                                         napi_value* result);
NAPI_EXTERN napi_status napi_delete_element(napi_env env,
                                            napi_value object,
                                            uint32_t index,
                                            bool* result);
NAPI_EXTERN napi_status
napi_define_properties(napi_env env,
                       napi_value object,
                       size_t property_count,
                       const napi_property_descriptor* properties);

// Methods to work with Arrays
NAPI_EXTERN napi_status napi_is_array(napi_env env,
                                      napi_value value,
                                      bool* result);
NAPI_EXTERN napi_status napi_get_array_length(napi_env env,
                                              napi_value value,
                                              uint32_t* result);

// Methods to compare values
NAPI_EXTERN napi_status napi_strict_equals(napi_env env,
                                           napi_value lhs,
                                           napi_value rhs,
                                           bool* result);

// Methods to work with Functions
NAPI_EXTERN napi_status napi_call_function(napi_env env,
                                           napi_value recv,
                                           napi_value func,
                                           size_t argc,
                                           const napi_value* argv,
                                           napi_value* result);
NAPI_EXTERN napi_status napi_new_instance(napi_env env,
                                          napi_value constructor,
                                          size_t argc,
                                          const napi_value* argv,
                                          napi_value* result);
NAPI_EXTERN napi_status napi_instanceof(napi_env env,
                                        napi_value object,
                                        napi_value constructor,
                                        bool* result);

// Methods to work with napi_callbacks

// Gets all callback info in a single call. (Ugly, but faster.)
NAPI_EXTERN napi_status napi_get_cb_info(
    napi_env env,               // [in] NAPI environment handle
    napi_callback_info cbinfo,  // [in] Opaque callback-info handle
    size_t* argc,      // [in-out] Specifies the size of the provided argv array
                       // and receives the actual count of args.
    napi_value* argv,  // [out] Array of values
    napi_value* this_arg,  // [out] Receives the JS 'this' arg for the call
    void** data);          // [out] Receives the data pointer for the callback.

NAPI_EXTERN napi_status napi_get_new_target(napi_env env,
                                            napi_callback_info cbinfo,
                                            napi_value* result);
NAPI_EXTERN napi_status
napi_define_class(napi_env env,
                  const char* utf8name,
                  size_t length,
                  napi_callback constructor,
                  void* data,
                  size_t property_count,
                  const napi_property_descriptor* properties,
                  napi_value* result);

// Methods to work with external data objects
NAPI_EXTERN napi_status napi_wrap(napi_env env,
                                  napi_value js_object,
                                  void* native_object,
                                  napi_finalize finalize_cb,
                                  void* finalize_hint,
                                  napi_ref* result);
NAPI_EXTERN napi_status napi_unwrap(napi_env env,
                                    napi_value js_object,
                                    void** result);
NAPI_EXTERN napi_status napi_remove_wrap(napi_env env,
                                         napi_value js_object,
                                         void** result);
NAPI_EXTERN napi_status napi_create_external(napi_env env,
                                             void* data,
                                             napi_finalize finalize_cb,
                                             void* finalize_hint,
                                             napi_value* result);
NAPI_EXTERN napi_status napi_get_value_external(napi_env env,
                                                napi_value value,
                                                void** result);

// Methods to control object lifespan

// Set initial_refcount to 0 for a weak reference, >0 for a strong reference.
NAPI_EXTERN napi_status napi_create_reference(napi_env env,
                                              napi_value value,
                                              uint32_t initial_refcount,
                                              napi_ref* result);

// Deletes a reference. The referenced value is released, and may
// be GC'd unless there are other references to it.
NAPI_EXTERN napi_status napi_delete_reference(napi_env env, napi_ref ref);

// Increments the reference count, optionally returning the resulting count.
// After this call the  reference will be a strong reference because its
// refcount is >0, and the referenced object is effectively "pinned".
// Calling this when the refcount is 0 and the object is unavailable
// results in an error.
NAPI_EXTERN napi_status napi_reference_ref(napi_env env,
                                           napi_ref ref,
                                           uint32_t* result);

// Decrements the reference count, optionally returning the resulting count.
// If the result is 0 the reference is now weak and the object may be GC'd
// at any time if there are no other references. Calling this when the
// refcount is already 0 results in an error.
NAPI_EXTERN napi_status napi_reference_unref(napi_env env,
                                             napi_ref ref,
                                             uint32_t* result);

// Attempts to get a referenced value. If the reference is weak,
// the value might no longer be available, in that case the call
// is still successful but the result is NULL.
NAPI_EXTERN napi_status napi_get_reference_value(napi_env env,
                                                 napi_ref ref,
                                                 napi_value* result);

NAPI_EXTERN napi_status napi_open_handle_scope(napi_env env,
                                               napi_handle_scope* result);
NAPI_EXTERN napi_status napi_close_handle_scope(napi_env env,
                                                napi_handle_scope scope);
NAPI_EXTERN napi_status
napi_open_escapable_handle_scope(napi_env env,
                                 napi_escapable_handle_scope* result);
NAPI_EXTERN napi_status
napi_close_escapable_handle_scope(napi_env env,
                                  napi_escapable_handle_scope scope);

NAPI_EXTERN napi_status napi_escape_handle(napi_env env,
                                           napi_escapable_handle_scope scope,
                                           napi_value escapee,
                                           napi_value* result);

// Methods to support error handling
NAPI_EXTERN napi_status napi_throw(napi_env env, napi_value error);
NAPI_EXTERN napi_status napi_throw_error(napi_env env,
                                         const char* code,
                                         const char* msg);
NAPI_EXTERN napi_status napi_throw_type_error(napi_env env,
                                         const char* code,
                                         const char* msg);
NAPI_EXTERN napi_status napi_throw_range_error(napi_env env,
                                         const char* code,
                                         const char* msg);
NAPI_EXTERN napi_status napi_is_error(napi_env env,
                                      napi_value value,
                                      bool* result);

// Methods to support catching exceptions
NAPI_EXTERN napi_status napi_is_exception_pending(napi_env env, bool* result);
NAPI_EXTERN napi_status napi_get_and_clear_last_exception(napi_env env,
                                                          napi_value* result);

// Methods to work with array buffers and typed arrays
NAPI_EXTERN napi_status napi_is_arraybuffer(napi_env env,
                                            napi_value value,
                                            bool* result);
NAPI_EXTERN napi_status napi_create_arraybuffer(napi_env env,
                                                size_t byte_length,
                                                void** data,
                                                napi_value* result);
NAPI_EXTERN napi_status
napi_create_external_arraybuffer(napi_env env,
                                 void* external_data,
                                 size_t byte_length,
                                 napi_finalize finalize_cb,
                                 void* finalize_hint,
                                 napi_value* result);
NAPI_EXTERN napi_status napi_get_arraybuffer_info(napi_env env,
                                                  napi_value arraybuffer,
                                                  void** data,
                                                  size_t* byte_length);
NAPI_EXTERN napi_status napi_is_typedarray(napi_env env,
                                           napi_value value,
                                           bool* result);
NAPI_EXTERN napi_status napi_create_typedarray(napi_env env,
                                               napi_typedarray_type type,
                                               size_t length,
                                               napi_value arraybuffer,
                                               size_t byte_offset,
                                               napi_value* result);
NAPI_EXTERN napi_status napi_get_typedarray_info(napi_env env,
                                                 napi_value typedarray,
                                                 napi_typedarray_type* type,
                                                 size_t* length,
                                                 void** data,
                                                 napi_value* arraybuffer,
                                                 size_t* byte_offset);

NAPI_EXTERN napi_status napi_create_dataview(napi_env env,
                                             size_t length,
                                             napi_value arraybuffer,
                                             size_t byte_offset,
                                             napi_value* result);
NAPI_EXTERN napi_status napi_is_dataview(napi_env env,
                                         napi_value value,
                                         bool* result);
NAPI_EXTERN napi_status napi_get_dataview_info(napi_env env,
                                               napi_value dataview,
                                               size_t* bytelength,
                                               void** data,
                                               napi_value* arraybuffer,
                                               size_t* byte_offset);

// version management
NAPI_EXTERN napi_status napi_get_version(napi_env env, uint32_t* result);

// Promises
NAPI_EXTERN napi_status napi_create_promise(napi_env env,
                                            napi_deferred* deferred,
                                            napi_value* promise);
NAPI_EXTERN napi_status napi_resolve_deferred(napi_env env,
                                              napi_deferred deferred,
                                              napi_value resolution);
NAPI_EXTERN napi_status napi_reject_deferred(napi_env env,
                                             napi_deferred deferred,
                                             napi_value rejection);
NAPI_EXTERN napi_status napi_is_promise(napi_env env,
                                        napi_value value,
                                        bool* is_promise);

// Running a script
NAPI_EXTERN napi_status napi_run_script(napi_env env,
                                        napi_value script,
                                        napi_value* result);

// Memory management
NAPI_EXTERN napi_status napi_adjust_external_memory(napi_env env,
                                                    int64_t change_in_bytes,
                                                    int64_t* adjusted_value);

// #if NAPI_VERSION >= 5

// Dates
NAPI_EXTERN napi_status napi_create_date(napi_env env,
                                         double time,
                                         napi_value* result);

NAPI_EXTERN napi_status napi_is_date(napi_env env,
                                     napi_value value,
                                     bool* is_date);

NAPI_EXTERN napi_status napi_get_date_value(napi_env env,
                                            napi_value value,
                                            double* result);

// Add finalizer for pointer
NAPI_EXTERN napi_status napi_add_finalizer(napi_env env,
                                           napi_value js_object,
                                           void* native_object,
                                           napi_finalize finalize_cb,
                                           void* finalize_hint,
                                           napi_ref* result);

// #endif  // NAPI_VERSION >= 5

// #if NAPI_VERSION >= 6

// BigInt
NAPI_EXTERN napi_status napi_create_bigint_int64(napi_env env,
                                                 int64_t value,
                                                 napi_value* result);
NAPI_EXTERN napi_status napi_create_bigint_uint64(napi_env env,
                                                  uint64_t value,
                                                  napi_value* result);
NAPI_EXTERN napi_status napi_create_bigint_words(napi_env env,
                                                 int sign_bit,
                                                 size_t word_count,
                                                 const uint64_t* words,
                                                 napi_value* result);
NAPI_EXTERN napi_status napi_get_value_bigint_int64(napi_env env,
                                                    napi_value value,
                                                    int64_t* result,
                                                    bool* lossless);
NAPI_EXTERN napi_status napi_get_value_bigint_uint64(napi_env env,
                                                     napi_value value,
                                                     uint64_t* result,
                                                     bool* lossless);
NAPI_EXTERN napi_status napi_get_value_bigint_words(napi_env env,
                                                    napi_value value,
                                                    int* sign_bit,
                                                    size_t* word_count,
                                                    uint64_t* words);

// Object
NAPI_EXTERN napi_status
napi_get_all_property_names(napi_env env,
                            napi_value object,
                            napi_key_collection_mode key_mode,
                            napi_key_filter key_filter,
                            napi_key_conversion key_conversion,
                            napi_value* result);

// Instance data
NAPI_EXTERN napi_status napi_set_instance_data(napi_env env,
                                               void* data,
                                               napi_finalize finalize_cb,
                                               void* finalize_hint);

NAPI_EXTERN napi_status napi_get_instance_data(napi_env env,
                                               void** data);
// #endif  // NAPI_VERSION >= 6

// #if NAPI_VERSION >= 7
// ArrayBuffer detaching
NAPI_EXTERN napi_status napi_detach_arraybuffer(napi_env env,
                                                napi_value arraybuffer);

NAPI_EXTERN napi_status napi_is_detached_arraybuffer(napi_env env,
                                                     napi_value value,
                                                     bool* result);
// #endif  // NAPI_VERSION >= 7

// #if NAPI_VERSION >= 8
// Type tagging
NAPI_EXTERN napi_status napi_type_tag_object(napi_env env,
                                             napi_value value,
                                             const napi_type_tag* type_tag);

NAPI_EXTERN napi_status
napi_check_object_type_tag(napi_env env,
                           napi_value value,
                           const napi_type_tag* type_tag,
                           bool* result);
NAPI_EXTERN napi_status napi_object_freeze(napi_env env,
                                           napi_value object);
NAPI_EXTERN napi_status napi_object_seal(napi_env env,
                                         napi_value object);
// #endif  // NAPI_VERSION >= 8

/*************************************************************************** +
 * 
 *  native_api.h
 * 
****************************************************************************/
#define NAPI_INNER_EXTERN __declspec(deprecated)

NAPI_EXTERN napi_status napi_fatal_exception(napi_env env, napi_value err);

NAPI_EXTERN napi_status napi_create_string_utf16(napi_env env,
                                                 const char16_t* str,
                                                 size_t length,
                                                 napi_value* result);

NAPI_EXTERN napi_status napi_get_value_string_utf16(napi_env env,
                                                    napi_value value,
                                                    char16_t* buf,
                                                    size_t bufsize,
                                                    size_t* result);

NAPI_EXTERN napi_status napi_type_tag_object(napi_env env,
                                             napi_value value,
                                             const napi_type_tag* type_tag);

NAPI_EXTERN napi_status napi_check_object_type_tag(napi_env env,
                                                   napi_value value,
                                                   const napi_type_tag* type_tag,
                                                   bool* result);

NAPI_INNER_EXTERN napi_status napi_adjust_external_memory(napi_env env,
                                                          int64_t change_in_bytes,
                                                          int64_t* adjusted_value);


/**
 * @brief Native detach callback of napi_coerce_to_native_binding_object that can be used to
 *        detach the js object and the native object.
 *
 * @since 11
 */
typedef void* (*napi_native_binding_detach_callback)(napi_env env, void* native_object, void* hint);
/**
 * @brief Native attach callback of napi_coerce_to_native_binding_object that can be used to
 *        bind the js object and the native object.
 *
 * @since 11
 */
typedef napi_value (*napi_native_binding_attach_callback)(napi_env env, void* native_object, void* hint);

NAPI_EXTERN napi_status napi_run_script_path(napi_env env, const char* path, napi_value* result);
NAPI_EXTERN napi_status napi_queue_async_work_with_qos(napi_env env, napi_async_work work, napi_qos_t qos);
NAPI_EXTERN napi_status napi_load_module(napi_env env, const char* path, napi_value* result);

/**
 * @brief The module is loaded through the NAPI. By default, the default object is exported from the module.
 *
 * @param env Current running virtual machine context.
 * @param path Path name of the module to be loaded, like @ohos.hilog.
 * @param module_info Path names of bundle and module, like com.example.application/entry.
 * @param result Result of loading a module, which is an exported object of the module.
 * @return Returns the function execution status.
 * @since 12
*/
NAPI_EXTERN napi_status napi_load_module_with_info(napi_env env,
                                                   const char* path,
                                                   const char* module_info,
                                                   napi_value* result);
NAPI_EXTERN napi_status napi_get_instance_data(napi_env env, void** data);
NAPI_EXTERN napi_status napi_set_instance_data(napi_env env,
                                               void* data,
                                               napi_finalize finalize_cb,
                                               void* finalize_hint);
NAPI_EXTERN napi_status napi_remove_env_cleanup_hook(napi_env env, void (*fun)(void* arg), void* arg);
NAPI_EXTERN napi_status napi_add_env_cleanup_hook(napi_env env, void (*fun)(void* arg), void* arg);
NAPI_EXTERN napi_status napi_remove_async_cleanup_hook(napi_async_cleanup_hook_handle remove_handle);
NAPI_EXTERN napi_status napi_add_async_cleanup_hook(napi_env env,
                                                    napi_async_cleanup_hook hook,
                                                    void* arg,
                                                    napi_async_cleanup_hook_handle* remove_handle);
NAPI_EXTERN napi_status napi_async_destroy(napi_env env,
                                           napi_async_context async_context);
NAPI_EXTERN napi_status napi_async_init(napi_env env,
                                        napi_value async_resource,
                                        napi_value async_resource_name,
                                        napi_async_context* result);
NAPI_EXTERN napi_status napi_close_callback_scope(napi_env env, napi_callback_scope scope);
NAPI_EXTERN napi_status napi_open_callback_scope(napi_env env,
                                                 napi_value resource_object,
                                                 napi_async_context context,
                                                 napi_callback_scope* result);
NAPI_EXTERN napi_status node_api_get_module_file_name(napi_env env, const char** result);
// Create JSObject with initial properties given by descriptors, note that property key must be String,
// and must can not convert to element_index, also all keys must not duplicate.
NAPI_EXTERN napi_status napi_create_object_with_properties(napi_env env,
                                                           napi_value* result,
                                                           size_t property_count,
                                                           const napi_property_descriptor* properties);
// Create JSObject with initial properties given by keys and values, note that property key must be String,
// and must can not convert to element_index, also all keys must not duplicate.
NAPI_EXTERN napi_status napi_create_object_with_named_properties(napi_env env,
                                                                 napi_value* result,
                                                                 size_t property_count,
                                                                 const char** keys,
                                                                 const napi_value* values);
/**
 * @brief This API sets native properties to a object and converts this js object to native binding object.
 *
 * @param[in] env Current running virtual machine context.
 * @param[in] js_object The JavaScript value to coerce.
 * @param[in] detach_cb Native callback that can be used to detach the js object and the native object.
 * @param[in] attach_cb Native callback that can be used to bind the js object and the native object.
 * @param[in] native_object User-provided native instance to pass to thr detach callback and attach callback.
 * @param[in] hint Optional hint to pass to the detach callback and attach callback.
 * @return Return the function execution status.
 * @since 11
 */
NAPI_EXTERN napi_status napi_coerce_to_native_binding_object(napi_env env,
                                                             napi_value js_object,
                                                             napi_native_binding_detach_callback detach_cb,
                                                             napi_native_binding_attach_callback attach_cb,
                                                             void* native_object,
                                                             void* hint);
NAPI_EXTERN napi_status napi_add_finalizer(napi_env env,
                                           napi_value js_object,
                                           void* native_object,
                                           napi_finalize finalize_cb,
                                           void* finalize_hint,
                                           napi_ref* result);
/**
 * @brief Create the ark runtime.
 *
 * @param env Indicates the ark runtime environment.
 * @since 12
 */
NAPI_EXTERN napi_status napi_create_ark_runtime(napi_env* env);

/**
 * @brief Destroy the ark runtime.
 *
 * @param env Indicates the ark runtime environment.
 * @since 12
 */
NAPI_EXTERN napi_status napi_destroy_ark_runtime(napi_env* env);

/*
 * @brief Defines a sendable class.
 *
 * @param env: The environment that the API is invoked under.
 * @param utf8name: Name of the ArkTS constructor function.
 * @param length: The length of the utf8name in bytes, or NAPI_AUTO_LENGTH if it is null-terminated.
 * @param constructor: Callback function that handles constructing instances of the class.
 * @param data: Optional data to be passed to the constructor callback as the data property of the callback info.
 * @param property_count: Number of items in the properties array argument.
 * @param properties: Array of property descriptors describing static and instance data properties, accessors, and
 * methods on the class. See napi_property_descriptor.
 * @param parent: A napi_value representing the Superclass.
 * @param result: A napi_value representing the constructor function for the class.
 * @return Return the function execution status.
 * @since 12
 */
NAPI_EXTERN napi_status napi_define_sendable_class(napi_env env,
                                                   const char* utf8name,
                                                   size_t length,
                                                   napi_callback constructor,
                                                   void* data,
                                                   size_t property_count,
                                                   const napi_property_descriptor* properties,
                                                   napi_value parent,
                                                   napi_value* result);

/**
 * @brief Queries a napi_value to check if it is sendable.
 *
 * @param env The environment that the API is invoked under.
 * @param value The napi_value to be checked.
 * @param result Boolean value that is set to true if napi_value is sendable, false otherwise.
 * @return Return the function execution status.
 * @since 12
 */
NAPI_EXTERN napi_status napi_is_sendable(napi_env env, napi_value value, bool* result);
/**
 * @brief Defines a sendable object.
 *
 * @param env The environment that the API is invoked under.
 * @param property_count The count of object properties.
 * @param properties Object properties.
 * @return Return the function execution status.
 * @since 12
 */
NAPI_EXTERN napi_status napi_create_sendable_object_with_properties(napi_env env, size_t property_count,
                                                                    const napi_property_descriptor* properties,
                                                                    napi_value* result);
/**
 * @brief Wraps a native instance in a ArkTS object.
 *
 * @param env The environment that the API is invoked under.
 * @param js_object The ArkTS object that will be the wrapper for the native object.
 * @param native_object The native instance that will be wrapped in the ArkTS object.
 * @param finalize_lib Optional native callback that can be used to free the native instance when the ArkTS object
 * has been garbage-collected.
 * @param finalize_hint Optional contextual hint that is passed to the finalize callback.
 * @return Return the function execution status.
 * @since 12
 */
NAPI_EXTERN napi_status napi_wrap_sendable(napi_env env, napi_value js_object, void* native_object,
                                           napi_finalize finalize_cb, void* finalize_hint);
/**
 * @brief Wraps a native instance in a ArkTS object.
 *
 * @param env The environment that the API is invoked under.
 * @param js_object The ArkTS object that will be the wrapper for the native object.
 * @param native_object The native instance that will be wrapped in the ArkTS object.
 * @param finalize_lib Optional native callback that can be used to free the native instance when the ArkTS object
 * has been garbage-collected.
 * @param finalize_hint Optional contextual hint that is passed to the finalize callback.
 * @param native_binding_size The size of native binding.
 * @return Return the function execution status.
 * @since 12
 */
NAPI_EXTERN napi_status napi_wrap_sendable_with_size(napi_env env, napi_value js_object, void* native_object,
                                                     napi_finalize finalize_cb, void* finalize_hint,
                                                     size_t native_binding_size);
/**
 * @brief Retrieves a native instance that was previously wrapped in a ArkTS object.
 *
 * @param env The environment that the API is invoked under.
 * @param js_object The object associated with the native instance.
 * @param result Pointer to the wrapped native instance.
 * @return Return the function execution status.
 * @since 12
 */
NAPI_EXTERN napi_status napi_unwrap_sendable(napi_env env, napi_value js_object, void** result);
/**
 * @brief Retrieves a native instance that was previously wrapped in a ArkTS object and removes the wrapping.
 *
 * @param env The environment that the API is invoked under.
 * @param js_object The object associated with the native instance.
 * @param result Pointer to the wrapped native instance.
 * @return Return the function execution status.
 * @since 12
 */
NAPI_EXTERN napi_status napi_remove_wrap_sendable(napi_env env, napi_value js_object, void** result);
/*
 * @brief Create a sendable array.
 *
 * @param env: The environment that the API is invoked under.
 * @param result: A napi_value representing a sendable array.
 * @return Return the function execution status.
 * @since 12
 */
NAPI_EXTERN napi_status napi_create_sendable_array(napi_env env, napi_value* result);

/*
 * @brief Create a sendable array with length.
 *
 * @param env: The environment that the API is invoked under.
 * @param length: The initial length of the sendable array.
 * @param result: A napi_value representing a sendable array.
 * @return Return the function execution status.
 * @since 12
 */
NAPI_EXTERN napi_status napi_create_sendable_array_with_length(napi_env env, size_t length, napi_value* result);

/*
 * @brief Create a sendable arraybuffer.
 *
 * @param env: The environment that the API is invoked under.
 * @param byte_length: The length in bytes of the sendable arraybuffer to create.
 * @param data: Pointer to the underlying byte buffer of the sendable arraybuffer.
 * @param result: A napi_value representing a sendable arraybuffer.
 * @return Return the function execution status.
 * @since 12
 */
NAPI_EXTERN napi_status napi_create_sendable_arraybuffer(napi_env env, size_t byte_length,
                                                         void** data, napi_value* result);

/*
 * @brief Create a sendable typedarray.
 *
 * @param env: The environment that the API is invoked under.
 * @param type: Scalar datatype of the elements within the sendable typedarray.
 * @param length: Number of elements in the typedarray.
 * @param arraybuffer: Sendable arraybuffer underlying the sendable typedarray.
 * @param byte_offset: The byte offset within the sendable arraybuffer from
 * which to start projecting the sendable typedarray.
 * @param result: A napi_value representing a sendable typedarray.
 * @return Return the function execution status.
 * @since 12
 */
NAPI_EXTERN napi_status napi_create_sendable_typedarray(napi_env env,
                                                        napi_typedarray_type type,
                                                        size_t length,
                                                        napi_value arraybuffer,
                                                        size_t byte_offset,
                                                        napi_value* result);

/**
 * @brief Run the event loop by the given env and running mode in current thread.
 *
 * Support to run the native event loop in an asynchronous native thread with the specified running mode.
 *
 * @param env Current running virtual machine context.
 * @param mode Indicates the running mode of the native event loop.
 * @return Return the function execution status.
 * @since 12
 */
NAPI_EXTERN napi_status napi_run_event_loop(napi_env env, napi_event_mode mode);

/**
 * @brief Stop the event loop in current thread.
 *
 * Support to stop the running event loop in current native thread.
 *
 * @param env Current running virtual machine context.
 * @return Return the function execution status.
 * @since 12
 */
NAPI_EXTERN napi_status napi_stop_event_loop(napi_env env);

/**
 * @brief Serialize a JS object.
 *
 * @param env Current running virtual machine context.
 * @param object The JavaScript value to serialize.
 * @param transfer_list List of data to transfer in transfer mode.
 * @param clone_list List of Sendable data to transfer in clone mode.
 * @param result Serialization result of the JS object.
 * @return Returns the function execution status.
 * @since 12
*/
NAPI_EXTERN napi_status napi_serialize(napi_env env,
                                       napi_value object,
                                       napi_value transfer_list,
                                       napi_value clone_list,
                                       void** result);

/**
 * @brief Restore serialization data to a ArkTS object.
 *
 * @param env Current running virtual machine context.
 * @param buffer Data to deserialize.
 * @param object ArkTS object obtained by deserialization.
 * @return Returns the function execution status.
 * @since 12
*/
NAPI_EXTERN napi_status napi_deserialize(napi_env env, void* buffer, napi_value* object);

/**
 * @brief Delete serialization data.
 *
 * @param env Current running virtual machine context.
 * @param buffer Data to delete.
 * @return Returns the function execution status.
 * @since 12
*/
NAPI_EXTERN napi_status napi_delete_serialization_data(napi_env env, void* buffer);

/**
 * @brief Dispatch a task with specified priority from a native thread to an ArkTS thread, the task will execute
 *        the given thread safe function.
 *
 * @param func Indicates the thread safe function.
 * @param data Indicates the data anticipated to be transferred to the ArkTS thread.
 * @param priority Indicates the priority of the task dispatched.
 * @param isTail Indicates the way of the task dispatched into the native event queue. When "isTail" is true,
 *        the task will be dispatched to the tail of the native event queue. Conversely, when "isTail" is false, the
 *        tasks will be dispatched to the head of the native event queue.
 * @return Return the function execution status.
 * @since 12
 */
NAPI_EXTERN napi_status napi_call_threadsafe_function_with_priority(napi_threadsafe_function func,
                                                                    void *data,
                                                                    napi_task_priority priority,
                                                                    bool isTail);
