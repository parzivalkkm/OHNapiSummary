package hust.cse.ohnapisummary.mapping;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.util.List;
import java.util.Map;

public class NAPISummary {
    String arkts_name;
    List<Map<String, String>> arkts_params;
    String arkts_return;
    String native_name;
    SummaryIR summary_ir;

    NAPISummary(String arkts_name, List<Map<String, String>> arkts_params, String arkts_return, String native_name) {
        this.arkts_name = arkts_name;
        this.arkts_params = arkts_params;
        this.arkts_return = arkts_return;
        this.native_name = native_name;
        this.summary_ir = new SummaryIR();
    }
}

class SummaryIR {
    List<String> params;
    Map<String, String> locals;
    List<Instruction> insts;
    String ret;

    static class Instruction {
        int id;
        String type;
        List<String> content;
        String dst;
        List<String> src;
    }
}