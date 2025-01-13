package hust.cse.ohnapisummary.env.funcs;

import com.bai.env.AbsEnv;
import com.bai.env.Context;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import hust.cse.ohnapisummary.util.NAPIValue;
import java.util.Set;

public class NapiCreateFunctionFunction extends NAPIFunctionBase {
    public NapiCreateFunctionFunction() {
        super(Set.of(
            "napi_create_function"
        ));
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {
        NAPIValue nv = NAPIFunctionBase.recordCall(context, calleeFunc);
    }
}
