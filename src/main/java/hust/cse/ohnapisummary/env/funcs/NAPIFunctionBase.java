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
    );

    public NAPIFunctionBase() {
        super(staticSymbols);
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
            ret = getParamKSet(calleeFunc, 3, inOutEnv);

        } else if (funcName.equals("napi_module_register")) {
            ret = getParamKSet(calleeFunc, 0, inOutEnv);
        }
        if (ret != null) {
            inOutEnv.set(retALoc, ret, true);
        }
    }
}
