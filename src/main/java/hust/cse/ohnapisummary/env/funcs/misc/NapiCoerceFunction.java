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

public class NapiCoerceFunction extends NAPIFunctionBase {

    public NapiCoerceFunction() {
        super(Set.of(
            //NAPI_EXTERN napi_status napi_coerce_to_bool(napi_env env,
            //                                            napi_value value,
            //                                            napi_value* result);
            //NAPI_EXTERN napi_status napi_coerce_to_number(napi_env env,
            //                                              napi_value value,
            //                                              napi_value* result);
            //NAPI_EXTERN napi_status napi_coerce_to_object(napi_env env,
            //                                              napi_value value,
            //                                              napi_value* result);
            //NAPI_EXTERN napi_status napi_coerce_to_string(napi_env env,
            //                                              napi_value value,
            //                                              napi_value* result);
            "napi_coerce_to_bool",
            "napi_coerce_to_number",
            "napi_coerce_to_object",
            "napi_coerce_to_string"
        ));
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {

        NAPIValue callNV = recordCall(context, calleeFunc); // 记录调用的nv
        // 处理返回值
        ALoc retALoc = getReturnALoc(calleeFunc, false);
        KSet retKset = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_STATUS, calleeFunc.getEntryPoint(), callNV, retALoc.getLen()* 8, calleeFunc, context, inOutEnv);
        inOutEnv.set(retALoc, retKset, true);

        // 向result中插入一个抽象值
        List<ALoc> alocs = getParamALocs(calleeFunc, 2, inOutEnv);
        // 记录这个返回值
        NAPIValue localNV = recordLocal(context, calleeFunc,2);
        // 向分析中写入一个抽象值
        KSet kSetForValue = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_VALUE, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize* 8, calleeFunc, context, inOutEnv);
        for (ALoc loc: alocs) {
            KSet ks = inOutEnv.get(loc);
            for (AbsVal val : ks) {
                ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                inOutEnv.set(ptr, kSetForValue, true); // *ptr = env
            }
        }


    }
}
