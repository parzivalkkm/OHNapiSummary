package hust.cse.ohnapisummary.env.funcs.arrays;

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

public class NapiArrayFunction extends NAPIFunctionBase {
    public NapiArrayFunction() {
        super(Set.of(
            //NAPI_EXTERN napi_status napi_create_array(napi_env env, napi_value* result);
            "napi_create_array",           // 用于在Node-API模块中向ArkTS层创建一个ArkTS数组对象。
            //NAPI_EXTERN napi_status napi_create_array_with_length(napi_env env,
            //                                                      size_t length,
            //                                                      napi_value* result);
            "napi_create_array_with_length",  // 用于在Node-API模块中向ArkTS层创建指定长度的ArkTS数组时。
            //NAPI_EXTERN napi_status napi_is_array(napi_env env,
            //                                      napi_value value,
            //                                      bool* result);
            "napi_is_array",                  // 用于在Node-API模块中判断一个napi_value值是否为数组。
            //NAPI_EXTERN napi_status napi_get_array_length(napi_env env,
            //                                              napi_value value,
            //                                              uint32_t* result);
            "napi_get_array_length"          // 用于在Node-API模块中获取ArkTS数组对象的长度。
        ));
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {

        NAPIValue callNV = recordCall(context, calleeFunc); // 记录调用的nv
        // 处理返回值
        ALoc retALoc = getReturnALoc(calleeFunc, false);
        KSet retKset = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_STATUS, calleeFunc.getEntryPoint(), callNV, retALoc.getLen()* 8, calleeFunc, context, inOutEnv);
        inOutEnv.set(retALoc, retKset, true);

        if(calleeFunc.getName().equals("napi_create_array")) {

            List<ALoc> alocs = getParamALocs(calleeFunc, 1, inOutEnv);
            NAPIValue localNV = recordLocal(context, calleeFunc, 1);
            KSet kSetForValue = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_VALUE, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize* 8, calleeFunc, context, inOutEnv);
            for (ALoc loc: alocs) {
                KSet ks = inOutEnv.get(loc);
                for (AbsVal val : ks) {
                    ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                    inOutEnv.set(ptr, kSetForValue, true); // *ptr = env
                }
            }
        } else if(calleeFunc.getName().equals("napi_create_array_with_length")) {
            // 向result中插入一个抽象值
            List<ALoc> alocs = getParamALocs(calleeFunc, 2, inOutEnv);
            // 记录这个返回值
            NAPIValue localNV = recordLocal(context, calleeFunc, 2);
            // 向分析中写入一个抽象值
            KSet kSetForValue = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_VALUE, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize * 8, calleeFunc, context, inOutEnv);
            for (ALoc loc : alocs) {
                KSet ks = inOutEnv.get(loc);
                for (AbsVal val : ks) {
                    ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                    inOutEnv.set(ptr, kSetForValue, true); // *ptr = env
                }
            }

        } else if(calleeFunc.getName().equals("napi_is_array")) {
            // 向result中插入一个抽象值
//            List<ALoc> alocs = getParamALocs(calleeFunc, 2, inOutEnv);
//            // 记录这个返回值
//            NAPIValue localNV = recordLocal(context, calleeFunc, 2);
//            // 向分析中写入一个抽象值
//            KSet kSetForValue = NAPIValueManager.getKSetForValue(TypeCategory.NUMBER, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize * 8, calleeFunc, context, inOutEnv);
//            for (ALoc loc : alocs) {
//                KSet ks = inOutEnv.get(loc);
//                for (AbsVal val : ks) {
//                    ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
//                    inOutEnv.set(ptr, kSetForValue, true); // *ptr = env
//                }
//            }

        } else if(calleeFunc.getName().equals("napi_get_array_length")) {
            // 向result中插入一个抽象值
            List<ALoc> alocs = getParamALocs(calleeFunc, 2, inOutEnv);
            // 记录这个返回值
            NAPIValue localNV = recordLocal(context, calleeFunc, 2);
            // 向分析中写入一个抽象值
            KSet kSetForValue = NAPIValueManager.getKSetForValue(TypeCategory.NUMBER, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize * 8, calleeFunc, context, inOutEnv);
            for (ALoc loc : alocs) {
                KSet ks = inOutEnv.get(loc);
                for (AbsVal val : ks) {
                    ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                    inOutEnv.set(ptr, kSetForValue, true); // *ptr = env
                }
            }

        }
    }
}
