package hust.cse.ohnapisummary.env.funcs;

import com.bai.env.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.PcodeOp;
import hust.cse.ohnapisummary.util.MyGlobalState;
import hust.cse.ohnapisummary.util.NAPIValue;
import hust.cse.ohnapisummary.util.NAPIValueManager;
import hust.cse.ohnapisummary.util.TypeCategory;

import java.util.List;
import java.util.Set;


public class NapiCreateDoubleFunction  extends NAPIFunctionBase {
    public NapiCreateDoubleFunction() {
        super(Set.of(
            "napi_create_double"
        ));
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {
        // napi_status napi_create_double(napi_env env, double value, napi_value* result);
        NAPIValue callNV = recordCall(context, calleeFunc); // 记录调用的nv

        // 向result中插入一个抽象值
        List<ALoc> alocs = getParamALocs(calleeFunc, 2, inOutEnv);
        Parameter param = calleeFunc.getParameter(2);
        DataType dataType = param.getDataType();
        for (ALoc loc: alocs) {
            KSet ks = inOutEnv.get(loc);
            for (AbsVal val : ks) {
                ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                NAPIValue localNV = recordLocal(context, calleeFunc, ptr);
                KSet env = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_VALUE, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize, calleeFunc, context, inOutEnv);
                assert env.getInnerSet().size() == 1;
                inOutEnv.set(ptr, env, true);
            }
        }

        // 处理返回值
        ALoc retALoc = getReturnALoc(calleeFunc, false);
        KSet retKset = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_STATUS, calleeFunc.getEntryPoint(), callNV, MyGlobalState.defaultPointerSize, calleeFunc, context, inOutEnv);
        inOutEnv.set(retALoc, retKset, true);
    }
}
