package hust.cse.ohnapisummary.checkers;

import com.bai.checkers.CheckerBase;
import com.bai.env.*;
import com.bai.env.funcs.externalfuncs.ExternalFunctionBase;
import com.bai.env.region.RegionBase;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.*;
import hust.cse.ohnapisummary.ir.Module;
import hust.cse.ohnapisummary.ir.inst.Call;
import hust.cse.ohnapisummary.ir.inst.Phi;
import hust.cse.ohnapisummary.ir.inst.Ret;
import hust.cse.ohnapisummary.ir.utils.Use;
import hust.cse.ohnapisummary.ir.utils.Value;
import hust.cse.ohnapisummary.ir.value.Top;
import hust.cse.ohnapisummary.ir.value.Null;
import hust.cse.ohnapisummary.util.MyGlobalState;
import hust.cse.ohnapisummary.util.NAPIValue;

import hust.cse.ohnapisummary.env.TaintMap;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

public class SummaryExporter extends CheckerBase {
    Module module = new Module();
    hust.cse.ohnapisummary.ir.Function currentIrFunction = new hust.cse.ohnapisummary.ir.Function();

    Map<NAPIValue, Value> napiValue_Value_Map;





    public SummaryExporter(String cwe, String version) {
        super(cwe, version);
    }


    /**
     * @param dataType datatype, 但是当解析vararg额外的参数的时候会是null
     * @param kSet 为了解码str
     * @param env 为了解码str
     * @param ident 为了解码str
     * @return 返回解析出的参数
     */
    private List<Value> decodeKSet(DataType dataType, KSet kSet, AbsEnv env, String ident) {
        List<Value> ret = new ArrayList<>();
        if (kSet == null) {
            return ret;
        }
        long taints = kSet.getTaints();
        List<NAPIValue> taintSourceList = TaintMap.getTaintSourceList(taints);
        for (NAPIValue napiValue: taintSourceList) {
            ret.add(decodeNapiValue(napiValue));
        }
        if (kSet.isTop()) {
            return ret;
        }
        // TODO: 处理值流
        for (AbsVal targetVal : kSet) {
            // 处理Heap region
            RegionBase region = targetVal.getRegion();


        }
        return ret;
    }

    /**
     * @param caller 调用此napi的函数
     * @param call   记录调用信息的call对象
     * @param napi   被调用的napi函数
     * @param env    调用时的环境
     * @return       返回解析出的参数（以IR Use的形式）
     */
    private List<hust.cse.ohnapisummary.ir.Instruction> decodeParams(Function caller, Call call, Function napi,AbsEnv env) {
        List<hust.cse.ohnapisummary.ir.Instruction> ret = new ArrayList<>();
        Parameter[] params = napi.getParameters();
        int paramSize = params.length;
        for (int i = 0; i < paramSize; i++) {
            Parameter param = napi.getParameter(i);
            String dataTypeName = param.getDataType().getName();
            // TODO: 处理env的类型
//            if (dataTypeName.equals("JNIEnv *") || dataTypeName.equals("JavaVM *")) {
//                call.operands.add(new Use(call, Null.instance));
//                continue;
//            }
            Logging.debug("param: "+param.getName()+" "+param.getDataType().getName());

            List<ALoc> alocs = getParamALocs(napi, i, env);

            // TODO: 处理va_list
            if (i == (paramSize-1) && isVaListAPI(call.target)){
                Logging.debug("encounter va_list");
            }

            // 解析参数
            List<Value> values = new ArrayList<>();
            for (ALoc aloc: alocs) {
                KSet kSet = env.get(aloc);
                values.addAll(decodeKSet(param.getDataType(), kSet, env,
                        String.format("Func %s Param %s %s",napi.getName(), param.getDataType().toString(), param.getName())));
            }
            call.operands.add(new Use(call, phiMerge(values, ret)));
        }

        // TODO: 处理varargs

        // 处理完成call对象，将其加入到currentIrFunction中的instructions中并返回
        ret.add(call);
        return ret;
    }

    /**
     * 获取函数的参数的ALoc
     * @param r 返回的IR指令
     * @param function 当前函数
     * @param exitEnv 函数退出时的环境
     */
    private List<hust.cse.ohnapisummary.ir.Instruction> decodeRetVal(Ret r, Function function, AbsEnv exitEnv) {
        List<hust.cse.ohnapisummary.ir.Instruction> ret = new ArrayList<>();
        ALoc aloc = ExternalFunctionBase.getReturnALoc(function, false);
        KSet kSet = exitEnv.get(aloc);
        if (kSet == null) {
            Logging.warn("Cannot find return value for "+function.getName());
            return ret;
        }

        List<Value> v = decodeKSet(function.getReturnType(), kSet, exitEnv,
                String.format("Func %s return value", function.getName()));
        r.operands.add(new Use(r, phiMerge(v, ret)));
        ret.add(r);
        return ret;
    }

    private Value decodeNapiValue(NAPIValue napiValue) {
        if (napiValue.isParamValue()) {
            return currentIrFunction.params.get(napiValue.getParamIndex());
        } else if (napiValue_Value_Map.containsKey(napiValue)) {
            return napiValue_Value_Map.get(napiValue);
        } else {
            Logging.warn("Reference to a future return value!!");
            Call c = new Call();
            napiValue_Value_Map.put(napiValue, c);
            return c;
        }
    }

    private boolean isVaListAPI(String target) {
        if (target == null) {
            return false;
        }
        if (target.equals("__vsprintf_chk")) {
            return true;
        }
        return target.endsWith("MethodV") || target.equals("NewObjectV");
    }

    private Value phiMerge(List<Value> vs, List<hust.cse.ohnapisummary.ir.Instruction> insts) {
        if (vs.size() == 0) {
            return new Top();
        }
        if (vs.size() == 1) {
            return vs.get(0);
        }
        Phi p = new Phi();
        for (Value v: vs) {
            p.operands.add(new Use(p, v));
        }
        insts.add(p);
        return p;
    }

    @Override
    public boolean check() {
        for(Map.Entry<NAPIValue, Context> ent: MyGlobalState.napiManager.callSites.entrySet()) {
            NAPIValue napiValue = ent.getKey();
            Context context = ent.getValue();
            long callSiteAddr = napiValue.callsite;

            Function caller = GlobalState.flatAPI.getFunctionContaining(GlobalState.flatAPI.toAddr(callSiteAddr));

            Function napiFunc = napiValue.getApi();
            if  (napiFunc == null) {
                Logging.error("Cannot find called external function for 0x"+Long.toHexString(callSiteAddr));
                continue;
            }

            AbsEnv absEnv = context.getAbsEnvIn().get(GlobalState.flatAPI.toAddr(callSiteAddr));
            if (absEnv == null) {
                Logging.error("Cannot find absEnv for 0x"+Long.toHexString(callSiteAddr));
                continue;
            }

            Call call = napiValue2Call(napiValue);
            napiValue_Value_Map.put(napiValue, call);
            // 解析参数，将其加入到currentIrFunction中的instructions中
            currentIrFunction.addAll(decodeParams(caller, call, napiFunc, absEnv));
        }
        // 解析返回值
        Function cur = MyGlobalState.currentFunction;
        if (!(cur.getReturnType() instanceof VoidDataType)) {
            boolean found = false;
            for (Context context : Context.getContext(cur)) {
                if (!isAllZero(context.getCallString())) {
                    continue;
                }
                found = true;
                // TODO get exit AbsEnv
                Ret r = new Ret();
                currentIrFunction.addAll(decodeRetVal(r, cur, new AbsEnv(context.getExitValue())));
            }
            if (!found) {
                Logging.error("Cannot find context for main func? "+cur.getName());
            }
        }

        return false;
    }

    private Call napiValue2Call(NAPIValue nv) {
        Call ret;

        if (napiValue_Value_Map.containsKey(nv)) {
            ret = (Call) napiValue_Value_Map.get(nv);
        } else {
            ret = new Call();
            ret.callsite = nv.callsite;
            ret.target = getIrFullName(nv.getApi());
            ret.callstring = nv.callstring;
        }
        if (ret.comments == null) {
            ret.comments = generateCallComments(ret.callstring, ret.callsite);
        }
        return ret;
    }


    // 下面是一些帮助函数，帮助生成Call对象
    private static String getIrFullName(Function func) {
        String full = func.getName(true);
        if (full != null) {
            if (full.startsWith("<EXTERNAL>::")) {
                return full.substring("<EXTERNAL>::".length());
            }
            return full;
        }
        return "(undefined)";
    }


    private static boolean isAllZero(long[] callString) {
        for (long l: callString) {
            if (l != 0) {
                return false;
            }
        }
        return true;
    }

    private static String generateCallComments(long[] callstring, long callsite) {
        StringJoiner sj;
        if (callstring == null) {
            return String.format("context: null, callsite: %s", describeAddr(callsite));
        } else if (callstring.length > 1) {
            sj = new StringJoiner(", ", "{", "}");
        } else {
            sj = new StringJoiner(", ");
        }
        for (long addr: callstring) {
            sj.add(describeAddr(addr));
        }
        return String.format("context: %s, callsite: %s", sj.toString(), describeAddr(callsite));
    }

    private static String describeAddr(long addr) {
        if (addr == 0) {
            return "[0]";
        }
        Function func = GlobalState.flatAPI.getFunctionContaining(GlobalState.flatAPI.toAddr(addr));
        return String.format("%s[%s]", func == null? "null":func.getName(), Long.toHexString(addr));
    }


}