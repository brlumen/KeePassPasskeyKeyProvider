using System.ComponentModel;

namespace KeePassFIDO2
{
	partial class FIDO2OptionsForm
	{
		/// <summary>
		/// Required designer variable.
		/// </summary>
		private IContainer components = null;

		/// <summary>
		/// Clean up any resources being used.
		/// </summary>
		/// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
		protected override void Dispose(bool disposing)
		{
			if (disposing && (components != null))
			{
				components.Dispose();
			}

			base.Dispose(disposing);
		}

		#region Windows Form Designer generated code

		/// <summary>
		/// Required method for Designer support - do not modify
		/// the contents of this method with the code editor.
		/// </summary>
		private void InitializeComponent()
		{
			this.buttonManageCredential = new System.Windows.Forms.Button();
			this.buttonDiagnostics = new System.Windows.Forms.Button();
			this.textBoxBottom = new System.Windows.Forms.TextBox();
			this.textBoxTop = new System.Windows.Forms.TextBox();
			this.SuspendLayout();
			// 
			// buttonManageCredential
			// 
			this.buttonManageCredential.Location = new System.Drawing.Point(10, 90);
			this.buttonManageCredential.Margin = new System.Windows.Forms.Padding(0, 20, 0, 0);
			this.buttonManageCredential.Name = "buttonManageCredential";
			this.buttonManageCredential.Size = new System.Drawing.Size(311, 25);
			this.buttonManageCredential.TabIndex = 1;
			this.buttonManageCredential.Text = "Управление Credential";
			this.buttonManageCredential.UseVisualStyleBackColor = true;
			this.buttonManageCredential.Click += new System.EventHandler(this.ManageCredentialButtonClick);
			// 
			// buttonDiagnostics
			// 
			this.buttonDiagnostics.Location = new System.Drawing.Point(10, 125);
			this.buttonDiagnostics.Margin = new System.Windows.Forms.Padding(0, 10, 0, 0);
			this.buttonDiagnostics.Name = "buttonDiagnostics";
			this.buttonDiagnostics.Size = new System.Drawing.Size(311, 25);
			this.buttonDiagnostics.TabIndex = 3;
			this.buttonDiagnostics.Text = "🔍 Диагностика PRF";
			this.buttonDiagnostics.UseVisualStyleBackColor = true;
			this.buttonDiagnostics.Click += new System.EventHandler(this.DiagnosticsButtonClick);
			// 
			// textBoxBottom
			// 
			this.textBoxBottom.BackColor = System.Drawing.SystemColors.Control;
			this.textBoxBottom.BorderStyle = System.Windows.Forms.BorderStyle.None;
			this.textBoxBottom.Dock = System.Windows.Forms.DockStyle.Bottom;
			this.textBoxBottom.Location = new System.Drawing.Point(9, 264);
			this.textBoxBottom.Multiline = true;
			this.textBoxBottom.Name = "textBoxBottom";
			this.textBoxBottom.ReadOnly = true;
			this.textBoxBottom.Size = new System.Drawing.Size(312, 60);
			this.textBoxBottom.TabIndex = 0;
			this.textBoxBottom.TabStop = false;
			this.textBoxBottom.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
			// 
			// textBoxTop
			// 
			this.textBoxTop.BackColor = System.Drawing.SystemColors.Control;
			this.textBoxTop.BorderStyle = System.Windows.Forms.BorderStyle.None;
			this.textBoxTop.Location = new System.Drawing.Point(10, 10);
			this.textBoxTop.Multiline = true;
			this.textBoxTop.Name = "textBoxTop";
			this.textBoxTop.ReadOnly = true;
			this.textBoxTop.Size = new System.Drawing.Size(310, 60);
			this.textBoxTop.TabIndex = 2;
			this.textBoxTop.TabStop = false;
			this.textBoxTop.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
			// 
			// FIDO2OptionsForm
			// 
			this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
			this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
			this.ClientSize = new System.Drawing.Size(330, 333);
			this.Controls.Add(this.buttonDiagnostics);
			this.Controls.Add(this.buttonManageCredential);
			this.Controls.Add(this.textBoxBottom);
			this.Controls.Add(this.textBoxTop);
			this.MaximizeBox = false;
			this.MinimizeBox = false;
			this.Name = "FIDO2OptionsForm";
			this.Padding = new System.Windows.Forms.Padding(9);
			this.ShowIcon = false;
			this.ShowInTaskbar = false;
			this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
			this.Text = "KeePassFIDO2 Options";
			this.ResumeLayout(false);
			this.PerformLayout();
		}

		private System.Windows.Forms.Button buttonManageCredential;
		private System.Windows.Forms.Button buttonDiagnostics;
		private System.Windows.Forms.TextBox textBoxBottom;
		private System.Windows.Forms.TextBox textBoxTop;

		#endregion
	}
}

