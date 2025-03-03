package hust.cse.ohnapisummary.env.funcs;

import com.bai.env.AbsEnv;
import com.bai.env.Context;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import hust.cse.ohnapisummary.util.NAPIValue;
import java.util.Set;

public class NapiSetNamedPropertyFunction extends NAPIFunctionBase {
    public NapiSetNamedPropertyFunction() {
        super(Set.of(
            "napi_set_named_property"
        ));
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {
        // NAPI_EXTERN napi_status napi_set_named_property(napi_env env,
        //                                          napi_value object,
        //                                          const char* utf8name,
        //                                          napi_value value);
        NAPIValue nv = NAPIFunctionBase.recordCall(context, calleeFunc);
    }
}
