using System.ComponentModel;

namespace KeePassPasskeyKeyProvider
{
	partial class RecoveryPhraseInputForm
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
			this.textBoxPhrase = new System.Windows.Forms.TextBox();
			this.labelError = new System.Windows.Forms.Label();
			this.buttons = new System.Windows.Forms.FlowLayoutPanel();
			this.buttonCancel = new System.Windows.Forms.Button();
			this.buttonOK = new System.Windows.Forms.Button();
			this.layout.SuspendLayout();
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
			this.layout.RowCount = 4;
			this.layout.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.layout.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.layout.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.layout.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.layout.Controls.Add(this.labelDescription, 0, 0);
			this.layout.Controls.Add(this.textBoxPhrase, 0, 1);
			this.layout.Controls.Add(this.labelError, 0, 2);
			this.layout.Controls.Add(this.buttons, 0, 3);
			//
			// labelDescription
			//
			this.labelDescription.AutoSize = true;
			this.labelDescription.Margin = new System.Windows.Forms.Padding(3, 3, 3, 12);
			this.labelDescription.MaximumSize = new System.Drawing.Size(520, 0);
			this.labelDescription.Name = "labelDescription";
			//
			// textBoxPhrase
			//
			this.textBoxPhrase.Font = new System.Drawing.Font("Consolas", 11F);
			this.textBoxPhrase.Margin = new System.Windows.Forms.Padding(3, 0, 3, 6);
			this.textBoxPhrase.Multiline = true;
			this.textBoxPhrase.Name = "textBoxPhrase";
			this.textBoxPhrase.Size = new System.Drawing.Size(520, 70);
			this.textBoxPhrase.TabIndex = 0;
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
			this.buttons.Controls.Add(this.buttonOK);
			//
			// buttonCancel
			//
			this.buttonCancel.DialogResult = System.Windows.Forms.DialogResult.Cancel;
			this.buttonCancel.Name = "buttonCancel";
			this.buttonCancel.Size = new System.Drawing.Size(90, 25);
			this.buttonCancel.TabIndex = 2;
			this.buttonCancel.Text = Strings.Cancel;
			this.buttonCancel.UseVisualStyleBackColor = true;
			//
			// buttonOK
			//
			this.buttonOK.Name = "buttonOK";
			this.buttonOK.Size = new System.Drawing.Size(90, 25);
			this.buttonOK.TabIndex = 1;
			this.buttonOK.Text = Strings.Open;
			this.buttonOK.UseVisualStyleBackColor = true;
			this.buttonOK.Click += new System.EventHandler(this.OkButtonClick);
			//
			// RecoveryPhraseInputForm
			//
			this.AcceptButton = this.buttonOK;
			this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
			this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
			this.AutoSize = true;
			this.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
			this.CancelButton = this.buttonCancel;
			this.ClientSize = new System.Drawing.Size(540, 200);
			this.Controls.Add(this.layout);
			this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
			this.MaximizeBox = false;
			this.MinimizeBox = false;
			this.Name = "RecoveryPhraseInputForm";
			this.ShowInTaskbar = false;
			this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
			this.Text = Strings.RecoveryInputTitle;
			this.layout.ResumeLayout(false);
			this.layout.PerformLayout();
			this.buttons.ResumeLayout(false);
			this.ResumeLayout(false);
			this.PerformLayout();
		}

		private System.Windows.Forms.TableLayoutPanel layout;
		private System.Windows.Forms.Label labelDescription;
		private System.Windows.Forms.TextBox textBoxPhrase;
		private System.Windows.Forms.Label labelError;
		private System.Windows.Forms.FlowLayoutPanel buttons;
		private System.Windows.Forms.Button buttonCancel;
		private System.Windows.Forms.Button buttonOK;

		#endregion
	}
}
