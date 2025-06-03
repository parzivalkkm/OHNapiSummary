package hust.cse.ohnapisummary.env.funcs.misc;

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

public class NapiErrorFunction extends NAPIFunctionBase {
    public NapiErrorFunction() {
        super(Set.of(
                //NAPI_EXTERN napi_status napi_create_error(napi_env env,
                //                                          napi_value code,
                //                                          napi_value msg,
                //                                          napi_value* result);
                //NAPI_EXTERN napi_status napi_create_type_error(napi_env env,
                //                                               napi_value code,
                //                                               napi_value msg,
                //                                               napi_value* result);
                //NAPI_EXTERN napi_status napi_create_range_error(napi_env env,
                //                                                napi_value code,
                //                                                napi_value msg,
                //                                                napi_value* result);
                //NAPI_EXTERN napi_status napi_throw(napi_env env, napi_value error);
                //NAPI_EXTERN napi_status napi_throw_error(napi_env env,
                //                                         const char* code,
                //                                         const char* msg);
                //NAPI_EXTERN napi_status napi_throw_type_error(napi_env env,
                //                                         const char* code,
                //                                         const char* msg);
                //NAPI_EXTERN napi_status napi_throw_range_error(napi_env env,
                //                                         const char* code,
                //                                         const char* msg);
                "napi_create_error",
                "napi_create_type_error",
                "napi_create_range_error",
                "napi_throw",
                "napi_throw_error",
                "napi_throw_type_error",
                "napi_throw_range_error"
        ));
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {

        NAPIValue callNV = recordCall(context, calleeFunc); // 记录调用的nv
        // 处理返回值
        ALoc retALoc = getReturnALoc(calleeFunc, false);
        KSet retKset = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_STATUS, calleeFunc.getEntryPoint(), callNV, retALoc.getLen()* 8, calleeFunc, context, inOutEnv);
        inOutEnv.set(retALoc, retKset, true);

        if (calleeFunc.getName().equals("napi_create_error") ||
            calleeFunc.getName().equals("napi_create_type_error") ||
            calleeFunc.getName().equals("napi_create_range_error")) {
            // 向result中插入一个抽象值
            List<ALoc> alocs = getParamALocs(calleeFunc, 3, inOutEnv);
            // 记录这个返回值
            NAPIValue localNV = recordLocal(context, calleeFunc,3);
            // 向分析中写入一个抽象值
            KSet kSetForValue = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_VALUE, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize* 8, calleeFunc, context, inOutEnv);
            for (ALoc loc: alocs) {
                KSet ks = inOutEnv.get(loc);
                for (AbsVal val : ks) {
                    ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                    inOutEnv.set(ptr, kSetForValue, true); // *ptr = env
                }
            }
        } else if (calleeFunc.getName().equals("napi_throw") ||
                   calleeFunc.getName().equals("napi_throw_error") ||
                   calleeFunc.getName().equals("napi_throw_type_error") ||
                   calleeFunc.getName().equals("napi_throw_range_error")) {
            // 这些函数不需要向result中插入抽象值
            // 直接返回即可
        }


    }
}
