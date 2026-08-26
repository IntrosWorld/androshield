package org.example.agentform;

import android.app.Activity;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.os.Bundle;
import android.view.MotionEvent;
import android.view.View;

/** Harmless canvas-only screen for validating screenshot-based UI exploration. */
public final class VisualActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(new VisualPad(this));
    }

    private static final class VisualPad extends View {
        private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private String result = "No key selected";
        private final String[] keys = {"7", "8", "9", "4", "5", "6", "1", "2", "3"};

        VisualPad(Activity activity) {
            super(activity);
            setBackgroundColor(Color.rgb(246, 248, 252));
            setImportantForAccessibility(IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS);
        }

        @Override protected void onDraw(Canvas canvas) {
            int width = getWidth();
            paint.setColor(Color.rgb(22, 32, 52));
            paint.setTextAlign(Paint.Align.CENTER);
            paint.setTextSize(50);
            paint.setFakeBoldText(true);
            canvas.drawText("Vision-only safe keypad", width / 2f, 130, paint);
            paint.setTextSize(30);
            paint.setFakeBoldText(false);
            paint.setColor(Color.rgb(70, 82, 105));
            canvas.drawText("Tap a number to test screenshot control", width / 2f, 190, paint);

            float gap = 24, left = 90, top = 290;
            float cell = (width - 2 * left - 2 * gap) / 3f;
            for (int i = 0; i < keys.length; i++) {
                int row = i / 3, col = i % 3;
                float x1 = left + col * (cell + gap), y1 = top + row * (cell + gap);
                paint.setColor(Color.rgb(226, 232, 240));
                canvas.drawRoundRect(x1, y1, x1 + cell, y1 + cell, 26, 26, paint);
                paint.setColor(Color.rgb(15, 23, 42));
                paint.setTextSize(54);
                canvas.drawText(keys[i], x1 + cell / 2f, y1 + cell * .68f, paint);
            }
            paint.setColor(Color.rgb(8, 145, 178));
            paint.setTextSize(36);
            canvas.drawText(result, width / 2f, top + 3 * (cell + gap) + 80, paint);
        }

        @Override public boolean onTouchEvent(MotionEvent event) {
            if (event.getAction() != MotionEvent.ACTION_UP) return true;
            float gap = 24, left = 90, top = 290;
            float cell = (getWidth() - 2 * left - 2 * gap) / 3f;
            for (int i = 0; i < keys.length; i++) {
                int row = i / 3, col = i % 3;
                float x1 = left + col * (cell + gap), y1 = top + row * (cell + gap);
                if (event.getX() >= x1 && event.getX() <= x1 + cell
                        && event.getY() >= y1 && event.getY() <= y1 + cell) {
                    result = "Selected " + keys[i];
                    invalidate();
                    return true;
                }
            }
            return true;
        }
    }
}
