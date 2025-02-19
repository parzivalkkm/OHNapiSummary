package hust.cse.ohnapisummary.env.funcs;

import com.bai.env.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.PcodeOp;
import hust.cse.ohnapisummary.util.MyGlobalState;
import hust.cse.ohnapisummary.util.NAPIValue;
import hust.cse.ohnapisummary.util.NAPIValueManager;
import hust.cse.ohnapisummary.util.TypeCategory;

import java.util.List;
import java.util.Set;

public class NapiGetValueStringUtf8Function extends NAPIFunctionBase {
    public NapiGetValueStringUtf8Function() {
        super(Set.of(
            "napi_get_value_string_utf8"
        ));
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {
        // napi_status napi_get_value_string_utf8(napi_env env,
        //                                       napi_value value,
        //                                       char* buf,
        //                                       size_t bufsize,
        //                                       size_t* result);
        NAPIValue callNV = recordCall(context, calleeFunc); // 记录调用的nv
        // 处理返回值
        ALoc retALoc = getReturnALoc(calleeFunc, false);
        KSet retKset = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_STATUS, calleeFunc.getEntryPoint(), callNV, retALoc.getLen()* 8, calleeFunc, context, inOutEnv);
        inOutEnv.set(retALoc, retKset, true);

        // 向buf写入
        // TODO buffer
        List<ALoc> alocs = getParamALocs(calleeFunc, 2, inOutEnv);
        Parameter param = calleeFunc.getParameter(2);
        for (ALoc loc: alocs) {
            KSet ks = inOutEnv.get(loc);
            for (AbsVal val : ks) {
                ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                NAPIValue localNV = recordLocal(context, calleeFunc,2);
                KSet env = NAPIValueManager.getKSetForValue(TypeCategory.BUFFER, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize* 8, calleeFunc, context, inOutEnv);
                assert env.getInnerSet().size() == 1;
                inOutEnv.set(ptr, env, true);
            }
        }


    }
}
