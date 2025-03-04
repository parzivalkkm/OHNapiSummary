package hust.cse.ohnapisummary.env.funcs.objects;

import com.bai.env.AbsEnv;
import com.bai.env.Context;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import hust.cse.ohnapisummary.env.funcs.NAPIFunctionBase;
import hust.cse.ohnapisummary.util.NAPIValue;
import java.util.Set;

public class NapiDefinePropertiesFunction extends NAPIFunctionBase {
    public NapiDefinePropertiesFunction() {
        super(Set.of(
            "napi_define_properties"
        ));
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {

        // NAPI_EXTERN napi_status
        //napi_define_properties(napi_env env,
        //                       napi_value object,
        //                       size_t property_count,
        //                       const napi_property_descriptor* properties);

        // TODO 处理注册有关问题

        NAPIValue nv = NAPIFunctionBase.recordCall(context, calleeFunc);

    }
}
