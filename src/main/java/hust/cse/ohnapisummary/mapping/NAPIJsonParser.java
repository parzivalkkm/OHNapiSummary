package hust.cse.ohnapisummary.mapping;

import com.bai.util.Logging;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonElement;
import ghidra.app.script.GhidraScript;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import hust.cse.ohnapisummary.util.MyGlobalState;

import java.util.ArrayList;
import java.util.Map;

import hust.cse.ohnapisummary.ir.value.Param;
import hust.cse.ohnapisummary.ir.utils.Type;

public class NAPIJsonParser {
    FlatProgramAPI flatapi;
    GhidraScript script;
    DataTypeManager manager;

    public NAPIJsonParser(FlatProgramAPI flatapi, GhidraScript script, DataTypeManager manager) {
        this.flatapi = flatapi;
        this.script = script;
        this.manager = manager;
    }

    public ArrayList<Map.Entry<Function, hust.cse.ohnapisummary.ir.Function>> run(JsonObject jsonObject) throws InvalidInputException, DuplicateNameException {
        ArrayList<Map.Entry<Function, hust.cse.ohnapisummary.ir.Function>> ret = new ArrayList<>();

        for (Map.Entry<String, JsonElement> e : jsonObject.entrySet()) {
            //        "add": {
            //        "arkts_name": "add",
            //        "params": [
            //            "number",
            //            "number"
            //        ],
            //        "arkts_return_type": "number"
            //    },
            JsonObject obj = e.getValue().getAsJsonObject();
            String name = obj.get("arkts_name").getAsString();
            String returnType = obj.get("arkts_return_type").getAsString();
            JsonArray params = obj.getAsJsonArray("params");

            Function f = getFunctionFromDescriptorList(name);

            hust.cse.ohnapisummary.ir.Function irFunc = new hust.cse.ohnapisummary.ir.Function();
            irFunc.name = name;
            // 添加参数
            int i=0;
            for (JsonElement para: params) {
                String paramType = para.getAsString();
                String pname = getNameByType(paramType, i);
                if (pname == null) { pname = "a"+String.valueOf(i); }
                irFunc.params.add(new Param(pname, new Type(null).setTypeDef(paramType)));
                i+=1;
            }

            // 添加返回类型
            irFunc.returnType = new Type(null).setTypeDef(returnType);

            ret.add(Map.entry(f, irFunc));
        }

        return ret;
    }

    private Function getFunctionFromDescriptorList(String fname) {
        for (NAPIDescriptor desc: MyGlobalState.dynRegNAPIList) {
            if (desc.utf8name.equals(fname)) {
                Function f = flatapi.getFunctionAt(desc.napi_callbback_method);
                if (f != null) {
                    return f;
                }else{
                    Logging.warn("Cannot find function for descriptor: "+fname);
                    return null;
                }
            }
        }
        Logging.warn("Cannot find function for descriptor: "+fname);
        return null;
    }

    public static String getNameByType(String t, int i) {
        if (i == 0 && t.equals("napi_env")) {
            return "napi_env";
        } else if (i == 1 && t.equals("napi_callback_info")) {
            return "napi_callback_info";
        }
        return null;
    }
}
