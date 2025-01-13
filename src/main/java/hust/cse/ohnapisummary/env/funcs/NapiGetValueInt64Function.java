package hust.cse.ohnapisummary.env.funcs;

import com.bai.env.AbsEnv;
import com.bai.env.Context;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import hust.cse.ohnapisummary.util.NAPIValue;
import java.util.Set;

public class NapiGetValueInt64Function extends NAPIFunctionBase {
    public NapiGetValueInt64Function() {
        super(Set.of(
            "napi_get_value_int64"
        ));
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {
        NAPIValue nv = NAPIFunctionBase.recordCall(context, calleeFunc);
    }
}
