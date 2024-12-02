package hust.cse.ohnapisummary.env.funcs;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.funcs.externalfuncs.ExternalFunctionBase;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import hust.cse.ohnapisummary.util.MyGlobalState;
import hust.cse.ohnapisummary.util.NAPIValue;

import java.util.Set;

public class NAPIFunctionBase extends ExternalFunctionBase {

    public static Address currentCallSite;

    private static final Set<String> staticSymbols = Set.of(
            "napi_define_properties",
            "napi_module_register"
//            "napi_get_value_double"
    );

    public NAPIFunctionBase() {
        super(staticSymbols);
    }

    @Override
    public void defineDefaultSignature(Function callFunction) {
    }

    public NAPIFunctionBase(Set<String> symbols) {
        super(symbols);
    }

    public static NAPIValue recordCall(Context ctx, Function api) {
        NAPIValue nv = new NAPIValue(ctx, api, currentCallSite.getOffset());
        MyGlobalState.napiManager.registerCall(nv, ctx);
        return nv;
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {
        String funcName = calleeFunc.getName();
        KSet ret = null;
        ALoc retALoc = getReturnALoc(calleeFunc, false);
        if (funcName.equals("napi_define_properties")) {
            NAPIValue nv = recordCall(context, calleeFunc);

        } else if (funcName.equals("napi_module_register")) {

        } else if (funcName.equals("napi_get_value_double")) {
            NAPIValue nv = recordCall(context, calleeFunc);

        }

        if (ret != null) {
            inOutEnv.set(retALoc, ret, true);
        }
    }
}
