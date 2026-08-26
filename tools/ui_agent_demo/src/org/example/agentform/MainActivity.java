package org.example.agentform;

import android.app.Activity;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

/** Harmless offline form used only to prove bounded UI-agent interaction. */
public final class MainActivity extends Activity {
    private EditText field(String hint, int inputType) {
        EditText value = new EditText(this);
        value.setHint(hint);
        value.setContentDescription(hint);
        value.setInputType(inputType);
        value.setSingleLine(true);
        value.setPadding(24, 20, 24, 20);
        return value;
    }

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(48, 72, 48, 48);

        TextView title = new TextView(this);
        title.setText("Safe synthetic profile form");
        title.setTextSize(24);
        layout.addView(title);

        EditText name = field("Full name", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PERSON_NAME);
        EditText email = field("Email address", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS);
        EditText password = field("Password", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        name.setId(View.generateViewId());
        email.setId(View.generateViewId());
        password.setId(View.generateViewId());
        layout.addView(name);
        layout.addView(email);
        layout.addView(password);

        TextView result = new TextView(this);
        result.setText("Not submitted");
        result.setPadding(0, 24, 0, 0);

        Button submit = new Button(this);
        submit.setText("Create test profile");
        submit.setContentDescription("Create test profile locally");
        submit.setOnClickListener(v -> result.setText(
                "Submitted locally: " + name.getText() + " / " + email.getText()));
        layout.addView(submit);
        layout.addView(result);
        setContentView(layout);
    }
}
