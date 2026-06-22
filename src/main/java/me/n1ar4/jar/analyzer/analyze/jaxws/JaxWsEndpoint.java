/*
 * GPLv3 License
 *
 * Copyright (c) 2022-2026 4ra1n (Jar Analyzer Team)
 *
 * This project is distributed under the GPLv3 license.
 *
 * https://github.com/jar-analyzer/jar-analyzer/blob/master/LICENSE
 */

package me.n1ar4.jar.analyzer.analyze.jaxws;

import me.n1ar4.jar.analyzer.core.reference.ClassReference;

import java.util.ArrayList;
import java.util.List;

@SuppressWarnings("all")
public class JaxWsEndpoint {
    private ClassReference.Handle className;
    private ClassReference classReference;
    private String serviceName;
    private String endpointInterface;
    private final List<JaxWsOperation> operations = new ArrayList<>();

    public ClassReference.Handle getClassName() {
        return className;
    }

    public void setClassName(ClassReference.Handle className) {
        this.className = className;
    }

    public ClassReference getClassReference() {
        return classReference;
    }

    public void setClassReference(ClassReference classReference) {
        this.classReference = classReference;
    }

    public String getServiceName() {
        return serviceName;
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    public String getEndpointInterface() {
        return endpointInterface;
    }

    public void setEndpointInterface(String endpointInterface) {
        this.endpointInterface = endpointInterface;
    }

    public List<JaxWsOperation> getOperations() {
        return operations;
    }

    public void addOperation(JaxWsOperation operation) {
        this.operations.add(operation);
    }
}
