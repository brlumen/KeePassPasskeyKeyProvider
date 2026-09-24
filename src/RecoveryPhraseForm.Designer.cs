using System.ComponentModel;

namespace KeePassPasskeyKeyProvider
{
	partial class RecoveryPhraseForm
	{
		private IContainer components = null;

		protected override void Dispose(bool disposing)
		{
			if (disposing && (components != null))
			{
				components.Dispose();
			}

			base.Dispose(disposing);
		}

		#region Windows Form Designer generated code

		private void InitializeComponent()
		{
			this.layout = new System.Windows.Forms.TableLayoutPanel();
			this.labelDescription = new System.Windows.Forms.Label();
			this.textBoxWords = new System.Windows.Forms.TextBox();
			this.panelCheck = new System.Windows.Forms.TableLayoutPanel();
			this.labelWord1 = new System.Windows.Forms.Label();
			this.textBoxWord1 = new System.Windows.Forms.TextBox();
			this.labelWord2 = new System.Windows.Forms.Label();
			this.textBoxWord2 = new System.Windows.Forms.TextBox();
			this.labelWord3 = new System.Windows.Forms.Label();
			this.textBoxWord3 = new System.Windows.Forms.TextBox();
			this.labelError = new System.Windows.Forms.Label();
			this.buttons = new System.Windows.Forms.FlowLayoutPanel();
			this.buttonCancel = new System.Windows.Forms.Button();
			this.buttonNext = new System.Windows.Forms.Button();
			this.buttonBack = new System.Windows.Forms.Button();
			this.layout.SuspendLayout();
			this.panelCheck.SuspendLayout();
			this.buttons.SuspendLayout();
			this.SuspendLayout();
			//
			// layout
			//
			this.layout.AutoSize = true;
			this.layout.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
			this.layout.ColumnCount = 1;
			this.layout.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
			this.layout.Dock = System.Windows.Forms.DockStyle.Fill;
			this.layout.Name = "layout";
			this.layout.Padding = new System.Windows.Forms.Padding(9);
			this.layout.RowCount = 5;
			this.layout.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.layout.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.layout.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.layout.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.layout.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.layout.Controls.Add(this.labelDescription, 0, 0);
			this.layout.Controls.Add(this.textBoxWords, 0, 1);
			this.layout.Controls.Add(this.panelCheck, 0, 2);
			this.layout.Controls.Add(this.labelError, 0, 3);
			this.layout.Controls.Add(this.buttons, 0, 4);
			//
			// labelDescription
			//
			this.labelDescription.AutoSize = true;
			this.labelDescription.Margin = new System.Windows.Forms.Padding(3, 3, 3, 12);
			this.labelDescription.MaximumSize = new System.Drawing.Size(520, 0);
			this.labelDescription.MinimumSize = new System.Drawing.Size(520, 0);
			this.labelDescription.Name = "labelDescription";
			//
			// textBoxWords
			//
			this.textBoxWords.BackColor = System.Drawing.SystemColors.Window;
			this.textBoxWords.Font = new System.Drawing.Font("Consolas", 12F);
			this.textBoxWords.Margin = new System.Windows.Forms.Padding(3, 0, 3, 12);
			this.textBoxWords.Multiline = true;
			this.textBoxWords.Name = "textBoxWords";
			this.textBoxWords.ReadOnly = true;
			this.textBoxWords.Size = new System.Drawing.Size(520, 90);
			this.textBoxWords.TabIndex = 0;
			this.textBoxWords.TabStop = false;
			//
			// panelCheck
			//
			this.panelCheck.AutoSize = true;
			this.panelCheck.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
			this.panelCheck.ColumnCount = 2;
			this.panelCheck.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
			this.panelCheck.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
			this.panelCheck.Margin = new System.Windows.Forms.Padding(0, 0, 0, 6);
			this.panelCheck.Name = "panelCheck";
			this.panelCheck.RowCount = 3;
			this.panelCheck.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.panelCheck.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.panelCheck.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.panelCheck.Controls.Add(this.labelWord1, 0, 0);
			this.panelCheck.Controls.Add(this.textBoxWord1, 1, 0);
			this.panelCheck.Controls.Add(this.labelWord2, 0, 1);
			this.panelCheck.Controls.Add(this.textBoxWord2, 1, 1);
			this.panelCheck.Controls.Add(this.labelWord3, 0, 2);
			this.panelCheck.Controls.Add(this.textBoxWord3, 1, 2);
			//
			// labelWord1
			//
			this.labelWord1.Anchor = System.Windows.Forms.AnchorStyles.Left;
			this.labelWord1.AutoSize = true;
			this.labelWord1.Name = "labelWord1";
			//
			// textBoxWord1
			//
			this.textBoxWord1.Name = "textBoxWord1";
			this.textBoxWord1.Size = new System.Drawing.Size(160, 20);
			this.textBoxWord1.TabIndex = 1;
			//
			// labelWord2
			//
			this.labelWord2.Anchor = System.Windows.Forms.AnchorStyles.Left;
			this.labelWord2.AutoSize = true;
			this.labelWord2.Name = "labelWord2";
			//
			// textBoxWord2
			//
			this.textBoxWord2.Name = "textBoxWord2";
			this.textBoxWord2.Size = new System.Drawing.Size(160, 20);
			this.textBoxWord2.TabIndex = 2;
			//
			// labelWord3
			//
			this.labelWord3.Anchor = System.Windows.Forms.AnchorStyles.Left;
			this.labelWord3.AutoSize = true;
			this.labelWord3.Name = "labelWord3";
			//
			// textBoxWord3
			//
			this.textBoxWord3.Name = "textBoxWord3";
			this.textBoxWord3.Size = new System.Drawing.Size(160, 20);
			this.textBoxWord3.TabIndex = 3;
			//
			// labelError
			//
			this.labelError.AutoSize = true;
			this.labelError.ForeColor = System.Drawing.Color.Firebrick;
			this.labelError.Margin = new System.Windows.Forms.Padding(3, 0, 3, 12);
			this.labelError.MaximumSize = new System.Drawing.Size(520, 0);
			this.labelError.Name = "labelError";
			//
			// buttons
			//
			this.buttons.Anchor = System.Windows.Forms.AnchorStyles.Right;
			this.buttons.AutoSize = true;
			this.buttons.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
			this.buttons.FlowDirection = System.Windows.Forms.FlowDirection.RightToLeft;
			this.buttons.Margin = new System.Windows.Forms.Padding(0);
			this.buttons.Name = "buttons";
			this.buttons.Controls.Add(this.buttonCancel);
			this.buttons.Controls.Add(this.buttonNext);
			this.buttons.Controls.Add(this.buttonBack);
			//
			// buttonCancel
			//
			this.buttonCancel.DialogResult = System.Windows.Forms.DialogResult.Cancel;
			this.buttonCancel.Name = "buttonCancel";
			this.buttonCancel.Size = new System.Drawing.Size(90, 25);
			this.buttonCancel.TabIndex = 6;
			this.buttonCancel.Text = "Отмена";
			this.buttonCancel.UseVisualStyleBackColor = true;
			//
			// buttonNext
			//
			this.buttonNext.AutoSize = true;
			this.buttonNext.MinimumSize = new System.Drawing.Size(90, 25);
			this.buttonNext.Name = "buttonNext";
			this.buttonNext.Padding = new System.Windows.Forms.Padding(8, 0, 8, 0);
			this.buttonNext.TabIndex = 4;
			this.buttonNext.UseVisualStyleBackColor = true;
			this.buttonNext.Click += new System.EventHandler(this.NextButtonClick);
			//
			// buttonBack
			//
			this.buttonBack.Name = "buttonBack";
			this.buttonBack.Size = new System.Drawing.Size(90, 25);
			this.buttonBack.TabIndex = 5;
			this.buttonBack.Text = "Назад";
			this.buttonBack.UseVisualStyleBackColor = true;
			this.buttonBack.Click += new System.EventHandler(this.BackButtonClick);
			//
			// RecoveryPhraseForm
			//
			this.AcceptButton = this.buttonNext;
			this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
			this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
			this.AutoSize = true;
			this.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
			this.CancelButton = this.buttonCancel;
			this.ClientSize = new System.Drawing.Size(540, 260);
			this.Controls.Add(this.layout);
			this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
			this.MaximizeBox = false;
			this.MinimizeBox = false;
			this.Name = "RecoveryPhraseForm";
			this.ShowInTaskbar = false;
			this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
			this.Text = "Фраза восстановления";
			this.layout.ResumeLayout(false);
			this.layout.PerformLayout();
			this.panelCheck.ResumeLayout(false);
			this.panelCheck.PerformLayout();
			this.buttons.ResumeLayout(false);
			this.ResumeLayout(false);
			this.PerformLayout();
		}

		private System.Windows.Forms.TableLayoutPanel layout;
		private System.Windows.Forms.Label labelDescription;
		private System.Windows.Forms.TextBox textBoxWords;
		private System.Windows.Forms.TableLayoutPanel panelCheck;
		private System.Windows.Forms.Label labelWord1;
		private System.Windows.Forms.TextBox textBoxWord1;
		private System.Windows.Forms.Label labelWord2;
		private System.Windows.Forms.TextBox textBoxWord2;
		private System.Windows.Forms.Label labelWord3;
		private System.Windows.Forms.TextBox textBoxWord3;
		private System.Windows.Forms.Label labelError;
		private System.Windows.Forms.FlowLayoutPanel buttons;
		private System.Windows.Forms.Button buttonCancel;
		private System.Windows.Forms.Button buttonNext;
		private System.Windows.Forms.Button buttonBack;

		#endregion
	}
}
