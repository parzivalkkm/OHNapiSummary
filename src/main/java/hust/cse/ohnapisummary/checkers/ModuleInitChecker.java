package hust.cse.ohnapisummary.checkers;

import com.bai.checkers.CheckerBase;
import com.bai.env.*;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.Reference;

import java.util.List;

public class ModuleInitChecker extends CheckerBase {
    public ModuleInitChecker(String cwe, String version) {
        super(cwe, version);
    }

    @Override
    public boolean check() {
        Logging.info("Checking ModuleInitChecker");
        List<Reference> references = Utils.getReferences(List.of("napi_define_properties"));
        for (Reference reference : references) {
            Address toAddress = reference.getToAddress();
            Address fromAddress = reference.getFromAddress();
            Function callee = GlobalState.flatAPI.getFunctionAt(toAddress);
            Function caller = GlobalState.flatAPI.getFunctionContaining(fromAddress);
            if (callee == null || caller == null) {
                continue;
            }
            Logging.info(fromAddress + ": " + caller.getName() + " -> " + toAddress + ": " + callee.getName());

            Logging.info("size: " + Context.getContext(callee).size());

            Parameter[] params = callee.getParameters();
            int paramSize = callee.getParameters().length;

            Logging.info("param size: " + paramSize);
            for (int i = 0; i < paramSize; i++) {
                Parameter param = params[i];
                Logging.info("param: " + param.getName());
                Logging.info("param type: " + param.getDataType().getName());
            }

//            for (Context context : Context.getContext(caller)) {
//                AbsEnv absEnv = context.getAbsEnvIn().get(fromAddress);
//                if (absEnv == null) {
//                    continue;
//                }
//
//                Parameter[] params = callee.getParameters();
//                int paramSize = callee.getParameters().length;
//
//                List<ALoc> alocs = getParamALocs(callee, paramSize - 1, absEnv);
//
//                for (ALoc aloc : alocs) {
//                    KSet ks = absEnv.get(aloc);
//
//                    for (AbsVal val: ks) {
//                        if (val.getRegion().isLocal()) {
//                            // TODO: resolve the descriptor
//                        }
//                    }
//                }
//
//            }


        }





        return false;
    }

}
