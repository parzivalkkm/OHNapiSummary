package hust.cse.ohnapisummary.ir.json;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import hust.cse.ohnapisummary.ir.Instruction;
import hust.cse.ohnapisummary.ir.inst.Call;
import hust.cse.ohnapisummary.ir.inst.Ret;
import hust.cse.ohnapisummary.ir.utils.Constant;
import hust.cse.ohnapisummary.ir.utils.Value;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class Function {

    public Function(hust.cse.ohnapisummary.ir.Function irFunc) {
        // 名词
        this.name = irFunc.name;

        // 参数
        for(hust.cse.ohnapisummary.ir.value.Param param: irFunc.params) {
            this.params.put("%" + param.name, param.type.toString());
        }

        // 指令
        Long lastCallSite = null;
        CallInst lastCallInst = null;
        Map<String, String> retsToAdd = new LinkedHashMap<>();

        for(hust.cse.ohnapisummary.ir.Instruction inst: irFunc.insts) {
            if(inst instanceof Call) {
                Call call = (Call) inst;
                Long callsite = call.callsite;

                // 特殊处理第一个call
                if (lastCallSite == null) {
                    lastCallSite = callsite;
                    lastCallInst = new CallInst();

                    lastCallInst.target = call.target;
                    for(hust.cse.ohnapisummary.ir.utils.Use use: call.operands) {
                        lastCallInst.operands.add(getValueName(use.value));
                    }

                }else if (!callsite.equals(lastCallSite)) {
                    // 是新的callsite
                    // 保存上一个call的ret
                    lastCallInst.rets = new LinkedHashMap<>(retsToAdd);
                    instructions.add(lastCallInst);

                    // 清空
                    retsToAdd.clear();
                    lastCallSite = callsite;
                    lastCallInst = new CallInst();

                    lastCallInst.target = call.target;
                    // 将操作数添加至lastCallInst
                    for(hust.cse.ohnapisummary.ir.utils.Use use: call.operands) {
                        lastCallInst.operands.add(getValueName(use.value));
                    }

                }
                // 将返回值添加至retsToAdd
                retsToAdd.put("%" + call.name, String.valueOf(call.returnValueIndex));


            } else{
                if(lastCallSite != null){
                    // 如果是call后的指令
                    // 保存并清空
                    lastCallInst.rets = new LinkedHashMap<>(retsToAdd);
                    instructions.add(lastCallInst);

                    retsToAdd.clear();
                    lastCallInst = null;
                    lastCallSite = null;
                }

                if (inst instanceof Ret) {

                    Ret ret = (Ret) inst;
                    RetInst retInst = new RetInst();
                    retInst.operand = getValueName(ret.operands.get(0).value);

                    instructions.add(retInst);

                }else if (inst instanceof hust.cse.ohnapisummary.ir.inst.Phi) {
                    hust.cse.ohnapisummary.ir.inst.Phi phi = (hust.cse.ohnapisummary.ir.inst.Phi) inst;
                    PhiInst phiInst = new PhiInst();
                    for(hust.cse.ohnapisummary.ir.utils.Use use: phi.operands) {
                        phiInst.operands.add(getValueName(use.value));
                    }
                    phiInst.ret = "%" + phi.name;

                    instructions.add(phiInst);
                }
            }



        }
    }

    String getValueName(Value value) {
        String str = value.toValueString();
        return str;
    }


    @SerializedName("name")
    String name;

    @SerializedName("params")
    Map<String, String> params = new LinkedHashMap<>();

    @SerializedName("instructions")
    List<Inst> instructions = new ArrayList<>();

    public class Inst{
        @SerializedName("type")
        String type;
    }
    public class CallInst extends Inst{
        CallInst() {
            type = "Call";
        }
        @SerializedName("target")
        String target;
        @SerializedName("rets")
        Map<String, String> rets = new LinkedHashMap<>();
        @SerializedName("operands")
        List<String> operands = new ArrayList<>();

    }

    public class RetInst extends Inst{
        RetInst() {
            type = "Ret";
        }
        @SerializedName("operand")
        String operand;
    }

    public class PhiInst extends Inst{
        PhiInst() {
            type = "Phi";
        }
        @SerializedName("operands")
        List<String> operands = new ArrayList<>();
        @SerializedName("ret")
        String ret;
    }
    
}
