package hust.cse.ohnapisummary.ir.value;

import hust.cse.ohnapisummary.ir.utils.Value;

public final class Top extends Value {
    @Override
    public String toValueString() {
        return "top";
    }

    @Override
    public boolean equals(Object o) {
        return this == o || o instanceof Top;
    }

    @Override
    public int hashCode() {
        return Top.class.hashCode();
    }
}
