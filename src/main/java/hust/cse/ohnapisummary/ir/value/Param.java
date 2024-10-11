package hust.cse.ohnapisummary.ir.value;

import hust.cse.ohnapisummary.ir.utils.Type;
import hust.cse.ohnapisummary.ir.utils.Value;

public class Param extends Value {
    public Param(String n, Type t) {
        name = n;
        type = t;
    }

    @Override
    public String toString() {
        return type.toString() + " " + name;
    }
}
