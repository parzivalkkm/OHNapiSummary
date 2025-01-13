package hust.cse.ohnapisummary.env.funcs;

import com.bai.env.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.PcodeOp;
import hust.cse.ohnapisummary.util.MyGlobalState;
import hust.cse.ohnapisummary.util.NAPIValue;
import hust.cse.ohnapisummary.util.NAPIValueManager;

import java.util.List;
import java.util.Set;

public class NapiGetValueDoubleFunction extends NAPIFunctionBase{
    public NapiGetValueDoubleFunction() {
        super(Set.of(
            "napi_get_value_double"
        ));
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {
        //NAPI_EXTERN napi_status napi_get_value_double(napi_env env,
        //                                              napi_value value,
        //                                              double* result);
        NAPIValue nv = recordCall(context, calleeFunc); // 记录调用的nv
        // TODO:还应该有一个记录参数的nv
        // 向result中插入一个抽象值
        List<ALoc> alocs = getParamALocs(calleeFunc, 2, inOutEnv);
        Parameter param = calleeFunc.getParameter(2);
        DataType dataType = param.getDataType();
        for (ALoc loc: alocs) {
            KSet ks = inOutEnv.get(loc);
            for (AbsVal val : ks) {
                ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                // TODO: 插入抽象值
                KSet env = NAPIValueManager.getKSetForValue(dataType, calleeFunc.getEntryPoint(), nv, MyGlobalState.defaultPointerSize*8, calleeFunc, context, inOutEnv);
                assert env.getInnerSet().size() == 1;
                inOutEnv.set(ptr, env, true);
            }
        }
    }
}
