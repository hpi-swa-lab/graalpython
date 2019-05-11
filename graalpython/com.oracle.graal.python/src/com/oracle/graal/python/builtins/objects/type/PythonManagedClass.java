/*
 * Copyright (c) 2017, 2019, Oracle and/or its affiliates.
 * Copyright (c) 2013, Regents of the University of California
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 * conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package com.oracle.graal.python.builtins.objects.type;

import static com.oracle.graal.python.nodes.SpecialAttributeNames.__DOC__;
import static com.oracle.graal.python.nodes.SpecialAttributeNames.__NAME__;
import static com.oracle.graal.python.nodes.SpecialAttributeNames.__QUALNAME__;

import java.util.Collections;
import java.util.Set;
import java.util.WeakHashMap;

import com.oracle.graal.python.PythonLanguage;
import com.oracle.graal.python.builtins.objects.PNone;
import com.oracle.graal.python.builtins.objects.cext.PythonClassNativeWrapper;
import com.oracle.graal.python.builtins.objects.object.PythonObject;
import com.oracle.graal.python.builtins.objects.type.TypeNodes.ComputeMroNode;
import com.oracle.graal.python.builtins.objects.type.TypeNodes.GetSubclassesNode;
import com.oracle.graal.python.nodes.PGuards;
import com.oracle.graal.python.runtime.sequence.storage.MroSequenceStorage;
import com.oracle.truffle.api.Assumption;
import com.oracle.truffle.api.CompilerAsserts;
import com.oracle.truffle.api.CompilerDirectives.CompilationFinal;
import com.oracle.truffle.api.CompilerDirectives.TruffleBoundary;
import com.oracle.truffle.api.object.Shape;

public abstract class PythonManagedClass extends PythonObject implements PythonAbstractClass {

    private final String className;

    @CompilationFinal(dimensions = 1) private PythonAbstractClass[] baseClasses;

    private final MroSequenceStorage methodResolutionOrder;

    private final Set<PythonAbstractClass> subClasses = Collections.newSetFromMap(new WeakHashMap<PythonAbstractClass, Boolean>());
    private final Shape instanceShape;
    private final FlagsContainer flags;

    /** {@code true} if the MRO contains a native class. */
    private boolean needsNativeAllocation;
    @CompilationFinal private Object sulongType;

    @TruffleBoundary
    public PythonManagedClass(LazyPythonClass typeClass, String name, Shape instanceShape, PythonAbstractClass... baseClasses) {
        super(typeClass, PythonLanguage.freshShape() /* do not inherit layout from the TypeClass */);
        this.className = name;

        this.methodResolutionOrder = new MroSequenceStorage(name, 0);

        if (baseClasses.length == 1 && baseClasses[0] == null) {
            this.baseClasses = new PythonAbstractClass[]{};
        } else {
            unsafeSetSuperClass(baseClasses);
        }

        this.flags = new FlagsContainer(getSuperClass());

        // Compute MRO
        this.methodResolutionOrder.setInternalArrayObject(ComputeMroNode.doSlowPath(this));
        computeNeedsNativeAllocation();

        setAttribute(__NAME__, getBaseName(name));
        setAttribute(__QUALNAME__, className);
        setAttribute(__DOC__, PNone.NONE);
        // provide our instances with a fresh shape tree
        this.instanceShape = instanceShape;
    }

    private static String getBaseName(String qname) {
        int lastDot = qname.lastIndexOf('.');
        if (lastDot != -1) {
            return qname.substring(lastDot + 1);
        }
        return qname;
    }

    public Assumption getLookupStableAssumption() {
        return methodResolutionOrder.getLookupStableAssumption();
    }

    /**
     * This method needs to be called if the mro changes. (currently not used)
     */
    public void lookupChanged() {
        CompilerAsserts.neverPartOfCompilation();
        methodResolutionOrder.lookupChanged();
        for (PythonAbstractClass subclass : getSubClasses()) {
            if (subclass != null) {
                subclass.lookupChanged();
            }
        }
    }

    public Shape getInstanceShape() {
        return instanceShape;
    }

    PythonAbstractClass getSuperClass() {
        return getBaseClasses().length > 0 ? getBaseClasses()[0] : null;
    }

    public MroSequenceStorage getMethodResolutionOrder() {
        return methodResolutionOrder;
    }

    String getName() {
        return className;
    }

    private void computeNeedsNativeAllocation() {
        for (PythonAbstractClass cls : getMethodResolutionOrder().getInternalClassArray()) {
            if (PGuards.isNativeClass(cls)) {
                needsNativeAllocation = true;
                return;
            }
        }
        needsNativeAllocation = false;
    }

    @Override
    @TruffleBoundary
    public void setAttribute(Object key, Object value) {
        invalidateFinalAttribute(key);
        super.setAttribute(key, value);
    }

    @TruffleBoundary
    public void invalidateFinalAttribute(Object key) {
        CompilerAsserts.neverPartOfCompilation();
        if (key instanceof String) {
            methodResolutionOrder.invalidateAttributeInMROFinalAssumptions((String) key);
        }
    }

    /**
     * This method supports initialization and solves boot-order problems and should not normally be
     * used.
     */
    private void unsafeSetSuperClass(PythonAbstractClass... newBaseClasses) {
        CompilerAsserts.neverPartOfCompilation();
        // TODO: if this is used outside bootstrapping, it needs to call
        // computeMethodResolutionOrder for subclasses.

        assert getBaseClasses() == null || getBaseClasses().length == 0;
        this.baseClasses = newBaseClasses;

        for (PythonAbstractClass base : getBaseClasses()) {
            if (base != null) {
                GetSubclassesNode.doSlowPath(base).add(this);
            }
        }
        this.methodResolutionOrder.setInternalArrayObject(ComputeMroNode.doSlowPath(this));
    }

    final Set<PythonAbstractClass> getSubClasses() {
        return subClasses;
    }

    @Override
    public String toString() {
        CompilerAsserts.neverPartOfCompilation();
        return String.format("<class '%s'>", className);
    }

    public PythonAbstractClass[] getBaseClasses() {
        return baseClasses;
    }

    public void setFlags(long flags) {
        this.flags.setValue(flags);
    }

    FlagsContainer getFlagsContainer() {
        return flags;
    }

    /**
     * Flags are copied from the initial dominant base class. However, classes may already be
     * created before the C API was initialized, i.e., flags were not set.
     */
    static final class FlagsContainer {
        PythonAbstractClass initialDominantBase;
        long flags;

        public FlagsContainer(PythonAbstractClass superClass) {
            this.initialDominantBase = superClass;
        }

        private void setValue(long flags) {
            if (initialDominantBase != null) {
                initialDominantBase = null;
            }
            this.flags = flags;
        }
    }

    public PythonClassNativeWrapper getClassNativeWrapper() {
        return (PythonClassNativeWrapper) super.getNativeWrapper();
    }

    public final Object getSulongType() {
        return sulongType;
    }

    @TruffleBoundary
    public final void setSulongType(Object dynamicSulongType) {
        this.sulongType = dynamicSulongType;
    }

    public boolean needsNativeAllocation() {
        return needsNativeAllocation;
    }

}
