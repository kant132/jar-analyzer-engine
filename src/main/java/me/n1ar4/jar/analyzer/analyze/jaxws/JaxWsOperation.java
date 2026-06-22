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

import me.n1ar4.jar.analyzer.core.reference.MethodReference;

@SuppressWarnings("all")
public class JaxWsOperation {
    private MethodReference.Handle methodName;
    private MethodReference methodReference;
    private boolean exclude;
    private String action;

    public MethodReference.Handle getMethodName() {
        return methodName;
    }

    public void setMethodName(MethodReference.Handle methodName) {
        this.methodName = methodName;
    }

    public MethodReference getMethodReference() {
        return methodReference;
    }

    public void setMethodReference(MethodReference methodReference) {
        this.methodReference = methodReference;
    }

    public boolean isExclude() {
        return exclude;
    }

    public void setExclude(boolean exclude) {
        this.exclude = exclude;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }
}
