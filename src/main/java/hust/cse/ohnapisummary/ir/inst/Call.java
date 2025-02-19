package hust.cse.ohnapisummary.ir.inst;

import hust.cse.ohnapisummary.ir.Instruction;

import java.util.Arrays;

public class Call extends Instruction {
    // keep sync with JNIValue
    public long[] callstring; // context+callsite
    public String target;
    public long callsite;
    public int returnValueIndex;

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
