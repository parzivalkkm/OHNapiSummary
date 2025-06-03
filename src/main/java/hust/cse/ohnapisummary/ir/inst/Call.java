package hust.cse.ohnapisummary.ir.inst;

import hust.cse.ohnapisummary.ir.Instruction;
import hust.cse.ohnapisummary.ir.utils.Use;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Call extends Instruction {
    // keep sync with JNIValue
    public long[] callstring; // context+callsite
    public String target;
    public long callsite;
    public int returnValueIndex;

    public List<Use> argsOperands = new ArrayList<>();

    public void setNormalReturn() {
        returnValueIndex = -1;
    }

    public void setIntrinsicReturn(int index) {
        returnValueIndex = index;
    }



    @Override
    public String getOpString() {
        return "Call "+target;
    }

    @Override
    public String toString() {
        if (callsite != 0) {
            if (comments == null) {
                comments = String.format("context: %s, callsite: 0x%s", Arrays.toString(callstring), Long.toHexString(callsite));
            } else {
                comments += String.format(" context: %s, callsite: 0x%s", Arrays.toString(callstring), Long.toHexString(callsite));
            }
        }
        return super.toString();
    }
}
