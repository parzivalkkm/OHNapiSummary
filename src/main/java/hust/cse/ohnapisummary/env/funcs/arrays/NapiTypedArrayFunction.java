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

public class NapiTypedArrayFunction extends NAPIFunctionBase {
    public NapiTypedArrayFunction() {
        super(Set.of(

            //NAPI_EXTERN napi_status napi_is_typedarray(napi_env env,
            //                                           napi_value value,
            //                                           bool* result);
            "napi_is_typedarray",
            //NAPI_EXTERN napi_status napi_create_typedarray(napi_env env,
            //                                               napi_typedarray_type type,
            //                                               size_t length,
            //                                               napi_value arraybuffer,
            //                                               size_t byte_offset,
            //                                               napi_value* result);
            "napi_create_typedarray",
            //NAPI_EXTERN napi_status napi_get_typedarray_info(napi_env env,
            //                                                 napi_value typedarray,
            //                                                 napi_typedarray_type* type,
            //                                                 size_t* length,
            //                                                 void** data,
            //                                                 napi_value* arraybuffer,
            //                                                 size_t* byte_offset);

            "napi_get_typedarray_info"
        ));
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {

        NAPIValue callNV = recordCall(context, calleeFunc); // 记录调用的nv
        // 处理返回值
        ALoc retALoc = getReturnALoc(calleeFunc, false);
        KSet retKset = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_STATUS, calleeFunc.getEntryPoint(), callNV, retALoc.getLen()* 8, calleeFunc, context, inOutEnv);
        inOutEnv.set(retALoc, retKset, true);

        if(calleeFunc.getName().equals("napi_create_typedarray")) {

            List<ALoc> alocs = getParamALocs(calleeFunc, 5, inOutEnv);
            NAPIValue localNV = recordLocal(context, calleeFunc, 5);
            KSet kSetForValue = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_VALUE, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize* 8, calleeFunc, context, inOutEnv);
            for (ALoc loc: alocs) {
                KSet ks = inOutEnv.get(loc);
                for (AbsVal val : ks) {
                    ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                    inOutEnv.set(ptr, kSetForValue, true); // *ptr = env
                }
            }
        } else if(calleeFunc.getName().equals("napi_is_typedarray")) {
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

        } else if(calleeFunc.getName().equals("napi_get_typedarray_info")) {
            // TODO 这里 3 4 5 6 都是返回值
            //NAPI_EXTERN napi_status napi_get_typedarray_info(napi_env env,
            //                                                 napi_value typedarray,
            //                                                 napi_typedarray_type* type,
            //                                                 size_t* length,
            //                                                 void** data,
            //                                                 napi_value* arraybuffer,
            //                                                 size_t* byte_offset);



            List<ALoc> alocs = getParamALocs(calleeFunc, 3, inOutEnv);
            // 记录这个返回值
            NAPIValue localNV = recordLocal(context, calleeFunc, 3);
            // 向分析中写入一个抽象值
            KSet kSetForValue = NAPIValueManager.getKSetForValue(TypeCategory.NUMBER, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize * 8, calleeFunc, context, inOutEnv);
            for (ALoc loc : alocs) {
                KSet ks = inOutEnv.get(loc);
                for (AbsVal val : ks) {
                    ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                    inOutEnv.set(ptr, kSetForValue, true);
                }
            }

            // TODO data

            alocs = getParamALocs(calleeFunc, 5, inOutEnv);
            // 记录这个返回值
            localNV = recordLocal(context, calleeFunc, 5);
            // 向分析中写入一个抽象值
            kSetForValue = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_VALUE, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize * 8, calleeFunc, context, inOutEnv);
            for (ALoc loc : alocs) {
                KSet ks = inOutEnv.get(loc);
                for (AbsVal val : ks) {
                    ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                    inOutEnv.set(ptr, kSetForValue, true);
                }
            }

            // 向result中插入一个抽象值
            alocs = getParamALocs(calleeFunc, 6, inOutEnv);
            // 记录这个返回值
            localNV = recordLocal(context, calleeFunc, 6);
            // 向分析中写入一个抽象值
            kSetForValue = NAPIValueManager.getKSetForValue(TypeCategory.NUMBER, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize * 8, calleeFunc, context, inOutEnv);
            for (ALoc loc : alocs) {
                KSet ks = inOutEnv.get(loc);
                for (AbsVal val : ks) {
                    ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                    inOutEnv.set(ptr, kSetForValue, true);
                }
            }

        }
    }
}
