import com.bai.util.*;
import ghidra.program.model.listing.Function;
import org.apache.commons.lang3.StringUtils;

import java.util.List;

public class OHNapiSummary extends BinAbsInspector {



    @Override
    public void run() throws Exception {
        long start = System.currentTimeMillis();
        // parse cmdline once
        Config conf = Config.HeadlessParser.parseConfig(StringUtils.join(getScriptArgs()).strip());
        if (conf.getNoOpt()) {
            println("Warning: disabling CalleeSavedReg optimization and local stack value passing optimization is only for experiment, and should not be enabled in most cases.");
        }
//        if (conf.getNoModel()) {
//            println("Warning: disabling function models is only for experiment, and should not be enabled in most cases.");
//            FuncCoverage.isNoModel = true;
//        }
//        // only enable detailed info in noModel mode. (for experiment)
//        Statistics stat = new Statistics(conf.getNoModel());
//        stat.addStatistics(conf.getTimeout(), getCurrentProgram().getFunctionManager());
//        println("Java home: "+System.getProperty("java.home"));
//
//        MyGlobalState.reset(this);
//        // setup external blocks
//        new EnvSetup(getCurrentProgram(), this, getState(), this).run();


        List<Function> napi_registers = this.getGlobalFunctions("RegisterEntryModule");
        if (napi_registers.size() != 1) {
            this.println("[ERROR] cannot find unique function RegisterEntryModule");
            if (napi_registers.isEmpty()) {
                this.println("[ERROR] skip function RegisterEntryModule");
            }
        }
        Function f = napi_registers.get(0);

        System.out.println("Found "+napi_registers.size()+" RegisterEntryModule functions.");

        // output some information about this function、
        println("Function name: "+f.getName());
        println("Function address: "+f.getEntryPoint());
        println("Function signature: "+f.getSignature());
        println("Function comment: "+f.getComment());


        long duration = System.currentTimeMillis() - start;

        println("OHNapiSummary script execution time: "+duration + "ms.");
    }
}
