package hust.cse.ohnapisummary.checkers;

import com.bai.checkers.CheckerBase;
import com.bai.env.*;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.Utils;
import com.caucho.hessian4.io.LocaleHandle;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.Reference;
import hust.cse.ohnapisummary.util.MyGlobalState;
import hust.cse.ohnapisummary.util.NAPIValue;

import java.util.List;
import java.util.Map;

public class ModuleInitChecker extends CheckerBase {
    public ModuleInitChecker(String cwe, String version) {
        super(cwe, version);
    }


    Reference reference = null;


    @Override
    public boolean check() {
        Logging.info("Checking ModuleInitChecker");
        for (Map.Entry<NAPIValue, Context> entry : MyGlobalState.napiManager.callSites.entrySet()) {
            NAPIValue napiValue = entry.getKey();
            Context context = entry.getValue();
            long callsite = napiValue.callsite;
            Function caller = GlobalState.flatAPI.getFunctionContaining(GlobalState.flatAPI.toAddr(callsite));
            Function callee = napiValue.getApi();
            if (callee == null) {
                Logging.error("Cannot find called external function for 0x" + Long.toHexString(callsite));
                continue;
            }
            AbsEnv absEnv = context.getAbsEnvIn().get(GlobalState.flatAPI.toAddr(callsite));
            if (absEnv == null) {
                Logging.error("Cannot find absEnv for 0x" + Long.toHexString(callsite));
                continue;
            }

            Parameter[] params = callee.getParameters();
            int paramSize = callee.getParameters().length;
            Logging.info("callee: " + callee);
            Logging.info("param size: " + paramSize);

//        Address toAddress = reference.getToAddress();
//        Address fromAddress = reference.getFromAddress();
//        Function callee = GlobalState.flatAPI.getFunctionAt(toAddress);
//        Function caller = GlobalState.flatAPI.getFunctionContaining(fromAddress);
//        if (callee == null || caller == null) {
//            Logging.error("callee or caller is null");
//            return false;
//        }
//        Logging.info("caller context: " + Context.getContext(caller).size());
//        Logging.info("callee context: " + Context.getContext(callee).size());
//
//        for (Context context : Context.getContext(caller)) {
//            AbsEnv absEnv = context.getAbsEnvIn().get(fromAddress);
//
//            if (absEnv == null) {
//                Logging.info("absEnv is null");
//                continue;
//            }
//
//            Logging.info("absEnv : " + absEnv);
//            // napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
//            // 首先获取第三个参数的值，得到动态注册的api个数
//            Parameter[] params = callee.getParameters();
//            int paramSize = callee.getParameters().length;
//            Logging.info("param size: " + paramSize);
//            for (int i = 0; i < paramSize; i++) {
//                Parameter p = params[i];
//                Logging.info("param: " + p.getName());
//                Logging.info("param data type: " + p.getDataType().getName());
//                List<ALoc> alocs = getParamALocs(callee, i, absEnv);
//                Logging.info("alocs size: " + alocs.size());
//            }


//                Parameter p = callee.getParameter(2);
//                Logging.info("param: " + p.getName());
//                Logging.info("param data type: " + p.getDataType().getName());
//                for (ALoc aloc : alocs) {
//                    KSet ks = absEnv.get(aloc);
//
//                    for (AbsVal val: ks) {
//                        if (val.getRegion().isLocal()) {
//                            Logging.info("local: " + val);
//                        }else{
//                            Logging.info("global: " + val);
//                        }
//                        resolveRegisteredAPIs(val, absEnv);
//                    }
//                }




        }
        return false;
    }


}
