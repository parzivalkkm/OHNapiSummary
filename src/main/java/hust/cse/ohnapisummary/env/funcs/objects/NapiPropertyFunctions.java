package hust.cse.ohnapisummary.env.funcs.objects;

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

public class NapiPropertyFunctions  extends NAPIFunctionBase {
    public NapiPropertyFunctions() {
        super(Set.of(

        //NAPI_EXTERN napi_status napi_get_property_names(napi_env env,
        //                                                napi_value object,
        //                                                napi_value* result);
        "napi_get_property_names",

        //NAPI_EXTERN napi_status napi_set_property(napi_env env,
        //                                          napi_value object,
        //                                          napi_value key,
        //                                          napi_value value);
        "napi_set_property",

        //NAPI_EXTERN napi_status napi_has_property(napi_env env,
        //                                          napi_value object,
        //                                          napi_value key,
        //                                          bool* result);
        "napi_has_property",

        //NAPI_EXTERN napi_status napi_get_property(napi_env env,
        //                                          napi_value object,
        //                                          napi_value key,
        //                                          napi_value* result);
        "napi_get_property",

        //NAPI_EXTERN napi_status napi_delete_property(napi_env env,
        //                                             napi_value object,
        //                                             napi_value key,
        //                                             bool* result);
        "napi_delete_property",

        //NAPI_EXTERN napi_status napi_has_own_property(napi_env env,
        //                                              napi_value object,
        //                                              napi_value key,
        //                                              bool* result);
        "napi_has_own_property",

        //NAPI_EXTERN napi_status napi_set_named_property(napi_env env,
        //                                          napi_value object,
        //                                          const char* utf8name,
        //                                          napi_value value);
        "napi_set_named_property",

        //NAPI_EXTERN napi_status napi_has_named_property(napi_env env,
        //                                          napi_value object,
        //                                          const char* utf8name,
        //                                          bool* result);
        "napi_has_named_property",

        //NAPI_EXTERN napi_status napi_get_named_property(napi_env env,
        //                                          napi_value object,
        //                                          const char* utf8name,
        //                                          napi_value* result);
        "napi_get_named_property",

        //napi_get_all_property_names(napi_env env,
        //                            napi_value object,
        //                            napi_key_collection_mode key_mode,
        //                            napi_key_filter key_filter,
        //                            napi_key_conversion key_conversion,
        //                            napi_value* result);
        "napi_get_all_property_names"
        ));
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {

        NAPIValue callNV = recordCall(context, calleeFunc); // 记录调用的nv
        // 处理返回值
        ALoc retALoc = getReturnALoc(calleeFunc, false);
        KSet retKset = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_STATUS, calleeFunc.getEntryPoint(), callNV, retALoc.getLen() * 8, calleeFunc, context, inOutEnv);
        inOutEnv.set(retALoc, retKset, true);


        if (calleeFunc.getName().equals("napi_get_property_names")) {
            // 向result中插入一个抽象值
            List<ALoc> alocs = getParamALocs(calleeFunc, 2, inOutEnv);
            NAPIValue localNV = recordLocal(context, calleeFunc, 2);
            KSet env = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_VALUE, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize * 8, calleeFunc, context, inOutEnv);
            for (ALoc loc : alocs) {
                KSet ks = inOutEnv.get(loc);
                for (AbsVal val : ks) {
                    ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                    inOutEnv.set(ptr, env, true);
                }
            }
        } else if (calleeFunc.getName().equals("napi_get_property") ||
                calleeFunc.getName().equals("napi_get_named_property")) {
            // 向result中插入一个抽象值
            List<ALoc> alocs = getParamALocs(calleeFunc, 3, inOutEnv);
            NAPIValue localNV = recordLocal(context, calleeFunc, 3);
            KSet env = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_VALUE, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize * 8, calleeFunc, context, inOutEnv);
            for (ALoc loc : alocs) {
                KSet ks = inOutEnv.get(loc);
                for (AbsVal val : ks) {
                    ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                    inOutEnv.set(ptr, env, true);
                }
            }
        } else if (calleeFunc.getName().equals("napi_has_property") ||
                calleeFunc.getName().equals("napi_delete_property") ||
                calleeFunc.getName().equals("napi_has_own_property") ||
                calleeFunc.getName().equals("napi_set_named_property") ||
                calleeFunc.getName().equals("napi_has_named_property")) {
            // 向result中插入一个抽象值
            List<ALoc> alocs = getParamALocs(calleeFunc, 3, inOutEnv);
            NAPIValue localNV = recordLocal(context, calleeFunc, 3);
            // Bool值记录为number
            KSet env = NAPIValueManager.getKSetForValue(TypeCategory.NUMBER, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize * 8, calleeFunc, context, inOutEnv);
            for (ALoc loc : alocs) {
                KSet ks = inOutEnv.get(loc);
                for (AbsVal val : ks) {
                    ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                    inOutEnv.set(ptr, env, true);
                }
            }
        } else if (calleeFunc.getName().equals("napi_get_all_property_names")) {
            // 向result中插入一个抽象值
            List<ALoc> alocs = getParamALocs(calleeFunc, 5, inOutEnv);
            NAPIValue localNV = recordLocal(context, calleeFunc, 5);

            KSet env = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_VALUE, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize * 8, calleeFunc, context, inOutEnv);
            for (ALoc loc : alocs) {
                KSet ks = inOutEnv.get(loc);
                for (AbsVal val : ks) {
                    ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                    inOutEnv.set(ptr, env, true);
                }
            }
            return;

        }
    }
}
