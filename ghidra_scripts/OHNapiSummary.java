import com.bai.env.funcs.FunctionModelManager;
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
        println("Java home: "+System.getProperty("java.home"));


        List<Function> napi_registers = this.getGlobalFunctions("RegisterEntryModule");

        System.out.println("Found "+napi_registers.size()+" RegisterEntryModule functions.");


        long duration = System.currentTimeMillis() - start;

        println("OHNapiSummary script execution time: "+duration + "ms.");
    }
}
