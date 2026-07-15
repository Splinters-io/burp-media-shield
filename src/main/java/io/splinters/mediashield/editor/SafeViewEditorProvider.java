package io.splinters.mediashield.editor;

import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;

/** Supplies a fresh {@link SafeViewEditor} for each message editor Burp creates. */
public final class SafeViewEditorProvider implements HttpResponseEditorProvider {

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext context) {
        return new SafeViewEditor();
    }
}
