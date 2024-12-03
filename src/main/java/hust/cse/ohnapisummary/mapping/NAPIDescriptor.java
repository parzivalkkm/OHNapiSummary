package hust.cse.ohnapisummary.mapping;

import ghidra.program.model.address.Address;

public class NAPIDescriptor {
    public String utf8name = "";
    public Address napi_value_name = null;
    public Address napi_callbback_method = null;
    public Address napi_callbback_getter = null;
    public Address napi_callbback_setter = null;
    public Address napi_value_value = null;
    public int attributes = -1;
    public Address data = null;

    NAPIDescriptor(String utf8name, Address napi_value_name, Address napi_callbback_method, Address napi_callbback_getter, Address napi_callbback_setter, Address napi_value_value, int attributes, Address data) {
        this.utf8name = utf8name;
        this.napi_value_name = napi_value_name;
        this.napi_callbback_method = napi_callbback_method;
        this.napi_callbback_getter = napi_callbback_getter;
        this.napi_callbback_setter = napi_callbback_setter;
        this.napi_value_value = napi_value_value;
        this.attributes = attributes;
        this.data = data;
    }

    public NAPIDescriptor(String utf8name, Address napi_callbback_method){
        this.utf8name = utf8name;
        this.napi_callbback_method = napi_callbback_method;
    }
}
