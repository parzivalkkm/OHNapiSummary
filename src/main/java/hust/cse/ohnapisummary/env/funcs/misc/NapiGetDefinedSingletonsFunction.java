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
import java.util.Map;
import java.util.Set;

public class NapiGetDefinedSingletonsFunction extends NAPIFunctionBase {

    public NapiGetDefinedSingletonsFunction() {

        //// Getters for defined singletons
        //NAPI_EXTERN napi_status napi_get_undefined(napi_env env, napi_value* result);
        //NAPI_EXTERN napi_status napi_get_null(napi_env env, napi_value* result);
        //NAPI_EXTERN napi_status napi_get_global(napi_env env, napi_value* result);
        //NAPI_EXTERN napi_status napi_get_boolean(napi_env env,
        //                                         bool value,
        //                                         napi_value* result);

        super(Set.of(
                "napi_get_undefined",
                "napi_get_null",
                "napi_get_global",
                "napi_get_boolean"
        ));
    }

    Map<String, Integer> returnIndex = Map.of(
            "napi_get_undefined", 1,
            "napi_get_null", 1,
            "napi_get_global", 1,
            "napi_get_boolean", 2
    );

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {



        NAPIValue callNV = recordCall(context, calleeFunc); // 记录调用的nv
        // 处理返回值
        ALoc retALoc = getReturnALoc(calleeFunc, false);
        KSet retKset = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_STATUS, calleeFunc.getEntryPoint(), callNV, retALoc.getLen()* 8, calleeFunc, context, inOutEnv);
        inOutEnv.set(retALoc, retKset, true);

        int returnIndex = this.returnIndex.get(calleeFunc.getName());
        // 向result中插入一个抽象值
        List<ALoc> alocs = getParamALocs(calleeFunc, returnIndex, inOutEnv);
        // 记录这个返回值
        NAPIValue localNV = recordLocal(context, calleeFunc,returnIndex);
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
