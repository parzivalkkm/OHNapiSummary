package hust.cse.ohnapisummary.env.funcs;

import com.bai.env.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import hust.cse.ohnapisummary.util.MyGlobalState;
import hust.cse.ohnapisummary.util.NAPIValue;
import hust.cse.ohnapisummary.util.NAPIValueManager;
import hust.cse.ohnapisummary.util.TypeCategory;

import java.util.List;
import java.util.Set;

public class NapiCallFunctionFunction extends NAPIFunctionBase {
    public NapiCallFunctionFunction() {
        super(Set.of(
                "napi_call_function"
        ));
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {
        //NAPI_EXTERN napi_status napi_call_function(napi_env env,
        //                                           napi_value recv,
        //                                           napi_value func,
        //                                           size_t argc,
        //                                           const napi_value* argv,
        //                                           napi_value* result);
        NAPIValue callNV = recordCall(context, calleeFunc); // 记录调用的nv
        // 处理返回值
        ALoc retALoc = getReturnALoc(calleeFunc, false);
        KSet retKset = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_STATUS, calleeFunc.getEntryPoint(), callNV, retALoc.getLen()* 8, calleeFunc, context, inOutEnv);
        inOutEnv.set(retALoc, retKset, true);

        // 向result中插入一个抽象值
        List<ALoc> alocs = getParamALocs(calleeFunc, 5, inOutEnv);
        // 记录这个返回值
        NAPIValue localNV = recordLocal(context, calleeFunc,5);
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
