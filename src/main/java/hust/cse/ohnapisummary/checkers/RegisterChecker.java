package hust.cse.ohnapisummary.checkers;

import com.bai.checkers.CheckerBase;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.Utils;
import com.sun.jna.platform.win32.WinDef;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

import java.util.List;


public class RegisterChecker  extends CheckerBase {
    public RegisterChecker(String cwe, String version) {
        super(cwe, version);
    }

    public Function moduleRegisterFunc;

    public Function trueRegisterFunction;

    @Override
    public boolean check() {
        Logging.info("Checking RegisterChecker");
        List<Reference> references = Utils.getReferences(List.of("napi_module_register"));
        for (Reference reference : references) {
            Address toAddress = reference.getToAddress();
            Address fromAddress = reference.getFromAddress();
            Function callee = GlobalState.flatAPI.getFunctionAt(toAddress);
            Function caller = GlobalState.flatAPI.getFunctionContaining(fromAddress);
            if (callee == null || caller == null) {
                continue;
            }
            Logging.info(fromAddress + ": " + caller.getName() + " -> " + toAddress + ": " + callee.getName());

            Logging.info("size: " + Context.getContext(caller).size());
            for (Context context : Context.getContext(caller)) {
                AbsEnv absEnv = context.getAbsEnvIn().get(fromAddress);
                if (absEnv == null) {
                    continue;
                }
                Address trueRegisterFunctionAddress = getTrueRegisterFunctionAddress(absEnv, callee);
                if (trueRegisterFunctionAddress != null) {
                    trueRegisterFunction = GlobalState.flatAPI.getFunctionAt(trueRegisterFunctionAddress);
                    return true;
                }
            }
        }




        return false;
    }



    private Address getTrueRegisterFunctionAddress(AbsEnv absEnv, Function callee) {
        String name = callee.getName();
        if (callee.getParameterCount() < 1) {
            // Skip the call since Ghidra didn't detect suitable number of arguments
            Logging.debug("Not enough parameters for \"" + name + "()\" function");
            return null;
        }
        KSet argKSet = getParamKSet(callee, 0, absEnv);
        Logging.info("KSet for argument: " + argKSet);

        for (AbsVal argAbsVal : argKSet) {
            Logging.info("Argument: " + argAbsVal);

        }
//        Address moduleStructAddr = GlobalState.flatAPI.toAddr(argAbsVal.getValue());
//        // 真正的注册函数地址在 module 结构体的第三个字段，即+0x10 处
//        Address thirdFieldAddr = moduleStructAddr.add(0x10);
//        Address trueRegisterFunctionAddress = GlobalState.flatAPI.toAddr(String.valueOf(thirdFieldAddr));
        return null;
    }
}
