package hust.cse.ohnapisummary.ir.json;

import java.util.ArrayList;
import java.util.List;
import com.google.gson.annotations.SerializedName;

public class Module {
    @SerializedName("module_name")
    public String moduleName;

    // 记录Module下所有函数信息
    @SerializedName("functions")
    public List<Function> allFunctions = new ArrayList<>();

}
