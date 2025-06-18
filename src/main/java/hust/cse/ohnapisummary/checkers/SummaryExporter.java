package hust.cse.ohnapisummary.checkers;

import com.bai.checkers.CheckerBase;
import com.bai.env.*;
import com.bai.env.funcs.externalfuncs.ExternalFunctionBase;
import com.bai.env.region.RegionBase;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.google.gson.Gson;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import hust.cse.ohnapisummary.ir.Module;
import hust.cse.ohnapisummary.ir.NumValueNamer;
import hust.cse.ohnapisummary.ir.inst.Call;
import hust.cse.ohnapisummary.ir.inst.Phi;
import hust.cse.ohnapisummary.ir.inst.Ret;
import hust.cse.ohnapisummary.ir.utils.Use;
import hust.cse.ohnapisummary.ir.utils.Value;
import hust.cse.ohnapisummary.ir.value.Null;
import hust.cse.ohnapisummary.ir.value.Top;
import hust.cse.ohnapisummary.ir.value.Number;
import hust.cse.ohnapisummary.ir.value.Str;
import hust.cse.ohnapisummary.util.MyGlobalState;
import hust.cse.ohnapisummary.util.NAPIValue;


import hust.cse.ohnapisummary.env.MyTaintMap;
import hust.cse.ohnapisummary.util.NAPIValueManager;
import hust.cse.ohnapisummary.util.TypeCategory;

import java.io.ByteArrayOutputStream;
import java.io.FileWriter;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class SummaryExporter extends CheckerBase {
    hust.cse.ohnapisummary.ir.json.Module module = new hust.cse.ohnapisummary.ir.json.Module();
    hust.cse.ohnapisummary.ir.Function currentIrFunction = new hust.cse.ohnapisummary.ir.Function();

    Map<NAPIValue, Value> napiValue_Value_Map;

    public SummaryExporter() {
        super("", "");
    }

    public void onStartFunc(hust.cse.ohnapisummary.ir.Function irFunc) {
        currentIrFunction = irFunc;
        napiValue_Value_Map = new HashMap<>();
    }

    public void onFinishFunc() {
        new NumValueNamer().visitFunc(currentIrFunction);
//        module.funcs.add(currentIrFunction);

        hust.cse.ohnapisummary.ir.json.Function jsonFunc = new hust.cse.ohnapisummary.ir.json.Function(currentIrFunction);

        module.allFunctions.add(jsonFunc);

        Gson gson = new Gson();
        String jsonString = gson.toJson(jsonFunc);

        currentIrFunction = null;

        napiValue_Value_Map = null;
    }

    public void export(FileWriter fw) {

        module.soName = MyGlobalState.soName;
        module.moduleName = MyGlobalState.moduleName;
        Gson gson = new Gson();

        String jsonString = gson.toJson(module);
        // 写入到文件里
        try {
            fw.write(jsonString);
            fw.flush();
        } catch (Exception e) {
            Logging.error("Cannot write to file: "+e.getMessage());
        }

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
        List<NAPIValue> taintSourceList = MyTaintMap.getTaintSourceList(taints);
        for (NAPIValue napiValue: taintSourceList) {
            // 将前面的taints加入到ret中(仅与数字相关)
            ret.add(decodeNapiValue(napiValue));
        }
        if (kSet.isTop()) {
            return ret;
        }
        // TODO: 处理值流
        for (AbsVal targetVal : kSet) {
            // 处理Heap region
            RegionBase region = targetVal.getRegion();
            if (region.isHeap() && MyGlobalState.napiManager.heapMap.containsKey(region)) {
                Logging.info("Decoding heap region");

                ret.add(decodeNapiValue(MyGlobalState.napiManager.heapMap.get(region)));
                // check Ffirst taint in heap
                KSet top = env.get(ALoc.getALoc(region, region.getBase(), 1));
                taints = top.getTaints();
                taintSourceList = MyTaintMap.getTaintSourceList(taints);
                Logging.info("Heap region taint source list: "+taintSourceList.size());
                for (NAPIValue jv : taintSourceList) {
                    Value v = decodeNapiValue(jv);
                    // 避免自己phi自己
                    if( !ret.contains(v)) {
                        ret.add(v);
                    }
                }

                continue;
            }

            // 如果没有具体的值，则返回Top
            if (!region.isGlobal() || targetVal.isBigVal()) {
                Logging.warn("Cannot decode Absval: "+targetVal.toString()); // + " at: " +  TODO
                ret.add(new Top());
                continue;
            }

            // 获取其具体值
            long id = targetVal.getValue();

            // 这个值保存的可能是给不透明值分配的id
            if (NAPIValueManager.highestBitsMatch(id)) { // special value
                NAPIValue v = MyGlobalState.napiManager.getValue(id);
                if (v == null) {
                    Logging.warn("Cannot find JNIValue?: "+Long.toHexString(id));
                } else {
                    ret.add(decodeNapiValue(v));
                    continue;
                }
            }

            // 这个值保存的还可能是一个地址，尝试对其进行解析
            long addr = id;
            String dtName;
            TypeCategory dtTc;
            if (dataType != null) {
                dtName = dataType.getName();
                dtTc = TypeCategory.byName(dataType);
            } else if (isPossibleStr(targetVal)) { // in rodata region
                dtName = "const char*";
                dtTc = null;
            } else {
                // TODO
                dtName= "int";
                dtTc = TypeCategory.NUMBER;
            }

            switch (dtName.replaceAll("\\s+","")) {
                case "constchar*":
                case "char*":
                    if (addr == 0) { // handle null
                        ret.add(new Null());
                        continue;
                    }
                    String s = decodeStr(env, targetVal);
                    ret.add(Str.of(s));
                    continue;
                // TODO 其他类型

                default:
                    break;
            }

            switch (dtTc) {
                case NAPI_CALLBACK_INFO:
                case NAPI_ENV:
                case NAPI_STATUS:
                case NAPI_VALUE:
                    Logging.error("不透明值应当已被处理");
                    break;
                case BUFFER:
                    Logging.error(String.format("Cannot decode buffer(%s): 0x%s", dataType != null ? dataType.toString(): dtName, Long.toHexString(addr)));
                    break;
                case NUMBER:
                    ret.add(Number.ofLong(addr));
                    break;
                default:
                case UNKNOWN:
                    if (!dtName.equals("undefined")) {
                        Logging.error("Unknown datatype "+dtName);
                    }
                    break;
            }


        }
        return ret;
    }

    boolean isPossibleStr(AbsVal val) {
        if (!val.getRegion().isGlobal()) {
            return false;
        }
        long addr_ = val.getValue();
        Address addr = GlobalState.flatAPI.toAddr(addr_);
        MemoryBlock mb = GlobalState.currentProgram.getMemory().getBlock(addr);
        if (mb == null) {
            return false;
        }
        return !mb.isWrite();
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
            Logging.info("param: "+param.getName()+" "+param.getDataType().getName());

            if (Objects.equals(napi.getName(), "napi_call_function") && i == 4){
                // 解析napi_call_function的第5个参数，args，需要解析list
                this.decodeArgsList(caller, call, napi, env, ret);
            }

            List<ALoc> alocs = getParamALocs(napi, i, env);

            // TODO: 处理va_list
            if (i == (paramSize-1) && isVaListAPI(call.target)){
                // 如果是最后一个参数，且这个api是va_list的
                // 那么对这个参数进行特殊处理
                Logging.info("encounter va_list");
            }



            // 解析参数
            List<Value> values = new ArrayList<>();
            for (ALoc aloc: alocs) {
                KSet kSet = env.get(aloc);
                values.addAll(decodeKSet(param.getDataType(), kSet, env,
                        String.format("Func %s Param %s %s",napi.getName(), param.getDataType().toString(), param.getName())));
            }
            // phi所有解析出来的use
            call.operands.add(new Use(call, phiMerge(values, ret)));
        }

        // TODO: 处理varargs

        if (napi.hasVarArgs()) {
            // 获取额外参数个数
            int totalArgNum = paramSize;
            HighFunction highFunc = null;
            if (caller != null) {
                highFunc = MyGlobalState.decom.decompileFunction(caller);
            }
            if (highFunc == null) {
                Logging.error("Decompilation for vararg failed.");
            } else {
                Iterator<PcodeOpAST> ops = highFunc.getPcodeOps(GlobalState.flatAPI.toAddr(call.callsite));
                for (Iterator<PcodeOpAST> it = ops; it.hasNext(); ) {
                    PcodeOpAST op = it.next();
                    int opcode = op.getOpcode();
                    // 跳过非call的指令
                    if (opcode <  PcodeOp.CALL || opcode > PcodeOp.CALLOTHER) {
                        continue;
                    }
//                    Logging.info(String.format("vararg call: \n  %s\ndecomp pcode: %s", call.toString(),
//                            MyGlobalState.pp.printOneWithAddr(op)));
                    Varnode[] ins = op.getInputs();
                    // 跳过那个call pcode指令的目标地址参数
                    totalArgNum = ins.length - 1;
                    Logging.info(String.format("Vararg call arg count at 0x%s: total %s, additional %s.",
                            Long.toHexString(call.callsite),
                            totalArgNum,
                            totalArgNum - paramSize));
                }
            }
            int startInd = paramSize;
            PrototypeModel cc = napi.getCallingConvention();
            if (cc == null) {
                cc = GlobalState.currentProgram.getCompilerSpec().getDefaultCallingConvention();
            }
            for(int i=startInd;i<totalArgNum;i++) {
                VariableStorage vs = cc.getArgLocation(i, params, null, GlobalState.currentProgram);
                assert vs.getVarnodeCount() == 1;
                Varnode node = vs.getLastVarnode();
                KSet ks = null;
                if (node != null) {
                    ALoc loc = null;
                    if (node.getAddress().isStackAddress()) {
                        AbsVal sp = getExactSpVal(env);
                        if (sp != null) {
                            loc = ALoc.getALoc(sp.getRegion(), sp.getValue()+node.getOffset(), MyGlobalState.defaultPointerSize);
                        } else {
                            Logging.warn(String.format("vararg no exact sp for %s at (%s)", napi.getName(), describeAddr(call.callsite)));
                        }
                    } else {
                        if (node.getSize() < MyGlobalState.defaultPointerSize) {
                            node = new Varnode(node.getAddress(), MyGlobalState.defaultPointerSize);
                        }
                        loc = ALoc.getALoc(node);

                    }

                    if (loc != null) {
                        ks = env.get(loc);
                    }
                }
                List<Value> v = decodeKSet(null, ks, env,
                        String.format("Func %s additional Param at: %s",napi.getName(), MyGlobalState.pp.printVarnode(node)));
                call.operands.add(new Use(call, phiMerge(v, ret)));
            }

        }

        ret.add(call);
        return ret;
    }

    private void decodeArgsList(Function caller, Call call, Function napi,AbsEnv env,List<hust.cse.ohnapisummary.ir.Instruction> insts){
        Logging.info("decoding args list");
        // 获取arglist长度，传入的是一个number
        List<ALoc> alocs = getParamALocs(napi, 3, env);
        long size = 0;
        for (ALoc loc: alocs) {
            KSet ks = env.get(loc);
            for (AbsVal val : ks) {
                size = val.getValue();
            }
        }
        Logging.info("napi_call_function argc is:" + size );
        if (size == 0) {
            Logging.warn("Cannot get argc or argc is 0");
            return;
        }

        // 分别解析每个参数
        Parameter param = napi.getParameter(4);
        // 获取p3传入值指向的地址，这里传入的时napi_value *，我们需要获取这个指针的值
        alocs = getParamALocs(napi, 4, env);
        ALoc starPtrAloc = null;

        for (ALoc loc: alocs) {
            KSet ks = env.get(loc);
            for (AbsVal val : ks) {
                ALoc ptr = ALoc.getALoc(val.getRegion(), val.getValue(), MyGlobalState.defaultPointerSize);
                starPtrAloc = ptr;
            }
        }
        long starPtr = starPtrAloc.getBegin();
        RegionBase region = starPtrAloc.getRegion();
        Logging.info("napi_call_function starPtr is a local value Region:" + region );

        for(int i=0; i<size;i++) {
            // 解析参数
            List<Value> values = new ArrayList<>();

            KSet kSet = env.get(starPtrAloc);
            values.addAll(decodeKSet(param.getDataType(), kSet, env,
                    String.format("Func %s Param %s %s",napi.getName(), param.getDataType().toString(), param.getName())));

            // phi所有解析出来的use
            call.argsOperands.add(new Use(call, phiMerge(values, insts)));

            // 获取下一个地址处的Aloc
            starPtr += MyGlobalState.defaultPointerSize;
            starPtrAloc = ALoc.getALoc(region, starPtr, MyGlobalState.defaultPointerSize);
        }

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
        // TODO: 要做出对应更改
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
        Logging.info("Exporting summaries for "+MyGlobalState.currentFunction.getName());

        Map<Long, Map<NAPIValue, Context>> callSite2Records = new LinkedHashMap<>();
        // 将同一处调用的NAPIValue合并
        for(Map.Entry<NAPIValue, Context> ent: MyGlobalState.napiManager.callsOrValues.entrySet()) {
            long callSiteAddr = ent.getKey().callSite;
            if (!callSite2Records.containsKey(callSiteAddr)) {
                callSite2Records.put(callSiteAddr, new LinkedHashMap<>());
            }
            // 按原顺序放在末尾
            callSite2Records.get(callSiteAddr).put(ent.getKey(), ent.getValue());

        }

        // 逐个调用处理
        Function currentCaller = null;
        Call currentCallInst = null;



        for(Map.Entry<Long, Map<NAPIValue, Context>> ent: callSite2Records.entrySet()) {

            long callSiteAddr = ent.getKey();
            Map<NAPIValue, Context> records = ent.getValue();

            currentCaller = GlobalState.flatAPI.getFunctionContaining(GlobalState.flatAPI.toAddr(callSiteAddr));
            if (currentCaller == null) {
                Logging.error("Cannot find caller for 0x"+Long.toHexString(callSiteAddr));
                continue;
            }

            List<hust.cse.ohnapisummary.ir.Instruction> insts = new ArrayList<>();

            // 首先处理记录调用和返回值的情况
            for(Map.Entry<NAPIValue, Context> ent2: records.entrySet()) {
                if (!ent2.getKey().isLocalValue()) {
                    NAPIValue napiValue = ent2.getKey();
                    Context context = ent2.getValue();
                    Function napiFunc = napiValue.getApi();
                    Logging.info("Decoding call to "+napiFunc.getName() + " at 0x"+Long.toHexString(callSiteAddr));
                    if (napiFunc == null) {
                        Logging.error("Cannot find called external function for 0x"+Long.toHexString(callSiteAddr));
                        continue;
                    }
                    AbsEnv absEnv = context.getAbsEnvIn().get(GlobalState.flatAPI.toAddr(callSiteAddr));
                    if (absEnv == null) {
                        Logging.error("Cannot find absEnv for 0x"+Long.toHexString(callSiteAddr));
                        continue;
                    }
                    // 只解析一次参数
                    currentCallInst = napiValue2Call(napiValue);
                    currentCallInst.setNormalReturn();
                    napiValue_Value_Map.put(napiValue, currentCallInst);
                    insts.addAll(decodeParams(currentCaller, currentCallInst, napiFunc, absEnv));
                    // 取出最后一个指令
                    currentCallInst = (Call) insts.get(insts.size()-1);
                } else {

                    // 然后处理通过参数返回的返回值

                    // 解析通过参数返回的返回值
                    NAPIValue napiValue = ent2.getKey();
                    // 复制一个currentCallInst对象
                    Call newCallInst = napiValue2Call(napiValue);
                    newCallInst.setIntrinsicReturn(napiValue.getRetIntoParamIndex());
                    napiValue_Value_Map.put(napiValue, newCallInst);
                    newCallInst.operands = currentCallInst.operands;
                    insts.add(newCallInst);
                }


            }
            // 然后处理通过参数返回的返回值

            currentIrFunction.addAll(insts);

        }

        // 解析整个函数的返回值
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
            ret.callsite = nv.callSite;
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


    private String decodeStr(AbsEnv env, AbsVal val) {
        if (!val.getRegion().isGlobal()) {
            Logging.warn("Cannot decode non global str ptr.");
            return null;
        }
        long addr = val.getValue();
        if (addr < 0x100) {
            return null;
        }
        byte[] bs = null;
        try {
            bs = getStringFromMemory(GlobalState.flatAPI.toAddr(addr));
        } catch (MemoryAccessException e) {
            Logging.error("JNI char* decode failed! 0x"+Long.toHexString(addr));
            return null;
        }
        if (bs == null) {
            return null;
        }
        String s;
        try {
            Charset csets = StandardCharsets.UTF_8;
            CharsetDecoder cd = csets.newDecoder();
            CharBuffer r = cd.decode(ByteBuffer.wrap(bs));
            s = r.toString();
        } catch (CharacterCodingException e) {
            s = Arrays.toString(bs);
        }
        return s;
    }

    public static byte[] getStringFromMemory(Address addr) throws MemoryAccessException {
        MemoryBlock mb = GlobalState.currentProgram.getMemory().getBlock(addr);
        if (mb == null) {
            Logging.error("Cannot decode string at 0x"+addr.toString());
            return null;
        }
        if (mb.isWrite()) {
            Logging.error("Constant str not from readonly section!");
        }
        StringBuilder sb = new StringBuilder();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while(mb.getByte(addr) != 0) {
            out.write(mb.getByte(addr));
            addr = addr.add(1);
        }
        return out.toByteArray();
    }

    public static AbsVal getExactSpVal(AbsEnv env) {
        KSet sp = env.get(ALoc.getSPALoc());
        if (sp.isTop() || sp.getInnerSet().size() > 1 || sp.getInnerSet().size() == 0) {
            return null;
        }
        AbsVal val = sp.iterator().next();
        if (val.getRegion().isLocal()) {
            return val;
        }
        return null;
    }


}