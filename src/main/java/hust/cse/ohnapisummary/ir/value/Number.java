package hust.cse.ohnapisummary.ir.value;

import hust.cse.ohnapisummary.ir.utils.Constant;
import hust.cse.ohnapisummary.ir.utils.Type;

public class Number extends Constant {
    public java.lang.Number val;
    public static Number ofLong(Long l) {
        Number v = new Number();
        v.val = l;
        v.type = Type.LONG;
        return v;
    }

    @Override
    public String toValueString() {
        return type.toString()+" "+val.toString();
    }
}
