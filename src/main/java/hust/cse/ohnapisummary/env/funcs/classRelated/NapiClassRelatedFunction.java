package hust.cse.ohnapisummary.env.funcs.classRelated;

import com.bai.env.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import hust.cse.ohnapisummary.env.funcs.NAPIFunctionBase;
import hust.cse.ohnapisummary.util.MyGlobalState;
import hust.cse.ohnapisummary.util.NAPIValue;
import hust.cse.ohnapisummary.util.NAPIValueManager;
import hust.cse.ohnapisummary.util.TypeCategory;

import java.util.List;
import java.util.Set;

public class NapiClassRelatedFunction extends NAPIFunctionBase {
    public NapiClassRelatedFunction() {
        super(Set.of(
            // NAPI_EXTERN napi_status napi_define_class(napi_env env,
            //                                           const char* utf8name,
            //                                           size_t length,
            //                                           napi_callback constructor,
            //                                           void* data,
            //                                           size_t property_count,
            //                                           const napi_property_descriptor* properties,
            //                                           napi_value* result);
            "napi_define_class",

            // NAPI_EXTERN napi_status napi_wrap(napi_env env,
            //                                   napi_value js_object,
            //                                   void* native_object,
            //                                   napi_finalize finalize_cb,
            //                                   void* finalize_hint,
            //                                   napi_ref* result);
            "napi_wrap",

            // NAPI_EXTERN napi_status napi_unwrap(napi_env env,
            //                                     napi_value js_object,
            //                                     void** result);
            "napi_unwrap",

            // NAPI_EXTERN napi_status napi_remove_wrap(napi_env env,
            //                                          napi_value js_object,
            //                                          void** result);
            "napi_remove_wrap",

            // NAPI_EXTERN napi_status napi_new_instance(napi_env env,
            //                                           napi_value constructor,
            //                                           size_t argc,
            //                                           const napi_value* argv,
            //                                           napi_value* result);
            "napi_new_instance",

            // NAPI_EXTERN napi_status napi_instanceof(napi_env env,
            //                                         napi_value object,
            //                                         napi_value constructor,
            //                                         bool* result);
            "napi_instanceof",

            // NAPI_EXTERN napi_status napi_get_new_target(napi_env env,
            //                                             napi_callback_info cbinfo,
            //                                             napi_value* result);
            "napi_get_new_target"
        ));
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {
        String funcName = calleeFunc.getName();
        
        // 记录调用
        NAPIValue callNV = recordCall(context, calleeFunc);
        
        // 处理返回值（所有这些函数都返回napi_status）
        ALoc retALoc = getReturnALoc(calleeFunc, false);
        KSet retKset = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_STATUS, 
            calleeFunc.getEntryPoint(), callNV, retALoc.getLen() * 8, calleeFunc, context, inOutEnv);
        inOutEnv.set(retALoc, retKset, true);

        switch (funcName) {
            case "napi_define_class":
                handleDefineClass(calleeFunc, inOutEnv, context);
                break;
            case "napi_wrap":
                handleWrap(calleeFunc, inOutEnv, context);
                break;
            case "napi_unwrap":
            case "napi_remove_wrap":
                handleUnwrap(calleeFunc, inOutEnv, context);
                break;
            case "napi_new_instance":
                handleNewInstance(calleeFunc, inOutEnv, context);
                break;
            case "napi_instanceof":
                handleInstanceof(calleeFunc, inOutEnv, context);
                break;
            case "napi_get_new_target":
                handleGetNewTarget(calleeFunc, inOutEnv, context);
                break;
        }
    }

    /**
     * 处理 napi_define_class 调用
     * napi_define_class(env, utf8name, length, constructor, data, property_count, properties, result)
     */
    private void handleDefineClass(Function calleeFunc, AbsEnv inOutEnv, Context context) {
        // 向result参数（第8个参数）写入一个抽象的napi_value
        List<ALoc> resultAlocs = getParamALocs(calleeFunc, 7, inOutEnv);
        NAPIValue localNV = recordLocal(context, calleeFunc, 7);
        
        KSet classConstructorKSet = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_VALUE, 
            calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize * 8, calleeFunc, context, inOutEnv);
        
        for (ALoc loc : resultAlocs) {
            KSet ks = inOutEnv.get(loc);
            for (AbsVal val : ks) {
                ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                inOutEnv.set(ptr, classConstructorKSet, true); // *result = class_constructor
            }
        }
    }

    /**
     * 处理 napi_wrap 调用
     * napi_wrap(env, js_object, native_object, finalize_cb, finalize_hint, result)
     */
    private void handleWrap(Function calleeFunc, AbsEnv inOutEnv, Context context) {
        // 如果有result参数（第6个参数），向其写入一个抽象的napi_ref
        List<ALoc> resultAlocs = getParamALocs(calleeFunc, 5, inOutEnv);
        if (!resultAlocs.isEmpty()) {
            NAPIValue localNV = recordLocal(context, calleeFunc, 5);
            
            KSet refKSet = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_REF, 
                calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize * 8, calleeFunc, context, inOutEnv);
            
            for (ALoc loc : resultAlocs) {
                KSet ks = inOutEnv.get(loc);
                for (AbsVal val : ks) {
                    ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                    inOutEnv.set(ptr, refKSet, true); // *result = napi_ref
                }
            }
        }
    }

    /**
     * 处理 napi_unwrap 和 napi_remove_wrap 调用
     * napi_unwrap(env, js_object, result)
     */
    private void handleUnwrap(Function calleeFunc, AbsEnv inOutEnv, Context context) {
        // 向result参数（第3个参数）写入一个抽象的指针值
        List<ALoc> resultAlocs = getParamALocs(calleeFunc, 2, inOutEnv);
        NAPIValue localNV = recordLocal(context, calleeFunc, 2);
        
        KSet nativeObjectKSet = NAPIValueManager.getKSetForValue(TypeCategory.POINTER, 
            calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize * 8, calleeFunc, context, inOutEnv);
        
        for (ALoc loc : resultAlocs) {
            KSet ks = inOutEnv.get(loc);
            for (AbsVal val : ks) {
                ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                inOutEnv.set(ptr, nativeObjectKSet, true); // *result = native_object_ptr
            }
        }
    }

    /**
     * 处理 napi_new_instance 调用
     * napi_new_instance(env, constructor, argc, argv, result)
     */
    private void handleNewInstance(Function calleeFunc, AbsEnv inOutEnv, Context context) {
        // 向result参数（第5个参数）写入一个抽象的napi_value（新实例）
        List<ALoc> resultAlocs = getParamALocs(calleeFunc, 4, inOutEnv);
        NAPIValue localNV = recordLocal(context, calleeFunc, 4);
        
        KSet instanceKSet = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_VALUE, 
            calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize * 8, calleeFunc, context, inOutEnv);
        
        for (ALoc loc : resultAlocs) {
            KSet ks = inOutEnv.get(loc);
            for (AbsVal val : ks) {
                ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                inOutEnv.set(ptr, instanceKSet, true); // *result = new_instance
            }
        }
    }

    /**
     * 处理 napi_instanceof 调用
     * napi_instanceof(env, object, constructor, result)
     */
    private void handleInstanceof(Function calleeFunc, AbsEnv inOutEnv, Context context) {
        // 向result参数（第4个参数）写入一个抽象的bool值
        List<ALoc> resultAlocs = getParamALocs(calleeFunc, 3, inOutEnv);
        NAPIValue localNV = recordLocal(context, calleeFunc, 3);
        
        KSet boolKSet = NAPIValueManager.getKSetForValue(TypeCategory.BOOLEAN, 
            calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize * 8, calleeFunc, context, inOutEnv);
        
        for (ALoc loc : resultAlocs) {
            KSet ks = inOutEnv.get(loc);
            for (AbsVal val : ks) {
                ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                inOutEnv.set(ptr, boolKSet, true); // *result = boolean
            }
        }
    }

    /**
     * 处理 napi_get_new_target 调用
     * napi_get_new_target(env, cbinfo, result)
     */
    private void handleGetNewTarget(Function calleeFunc, AbsEnv inOutEnv, Context context) {
        // 向result参数（第3个参数）写入一个抽象的napi_value（new.target）
        List<ALoc> resultAlocs = getParamALocs(calleeFunc, 2, inOutEnv);
        NAPIValue localNV = recordLocal(context, calleeFunc, 2);
        
        KSet newTargetKSet = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_VALUE, 
            calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize * 8, calleeFunc, context, inOutEnv);
        
        for (ALoc loc : resultAlocs) {
            KSet ks = inOutEnv.get(loc);
            for (AbsVal val : ks) {
                ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                inOutEnv.set(ptr, newTargetKSet, true); // *result = new_target
            }
        }
    }
}
