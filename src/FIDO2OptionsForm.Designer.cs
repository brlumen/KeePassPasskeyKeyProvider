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
			this.textBoxTop = new System.Windows.Forms.TextBox();
			this.groupBoxHello = new System.Windows.Forms.GroupBox();
			this.checkedListCredentials = new System.Windows.Forms.CheckedListBox();
			this.labelHelloStatus = new System.Windows.Forms.Label();
			this.buttonDeleteChecked = new System.Windows.Forms.Button();
			this.buttonRefresh = new System.Windows.Forms.Button();
			this.progressBar = new System.Windows.Forms.ProgressBar();
			this.buttonDiagnostics = new System.Windows.Forms.Button();
			this.groupBoxHello.SuspendLayout();
			this.SuspendLayout();
			//
			// textBoxTop
			//
			this.textBoxTop.BackColor = System.Drawing.SystemColors.Control;
			this.textBoxTop.BorderStyle = System.Windows.Forms.BorderStyle.None;
			this.textBoxTop.Location = new System.Drawing.Point(12, 12);
			this.textBoxTop.Multiline = true;
			this.textBoxTop.Name = "textBoxTop";
			this.textBoxTop.ReadOnly = true;
			this.textBoxTop.Size = new System.Drawing.Size(536, 48);
			this.textBoxTop.TabIndex = 0;
			this.textBoxTop.TabStop = false;
			//
			// groupBoxHello
			//
			this.groupBoxHello.Controls.Add(this.checkedListCredentials);
			this.groupBoxHello.Controls.Add(this.labelHelloStatus);
			this.groupBoxHello.Controls.Add(this.buttonDeleteChecked);
			this.groupBoxHello.Controls.Add(this.buttonRefresh);
			this.groupBoxHello.Controls.Add(this.progressBar);
			this.groupBoxHello.Location = new System.Drawing.Point(12, 68);
			this.groupBoxHello.Name = "groupBoxHello";
			this.groupBoxHello.Size = new System.Drawing.Size(536, 262);
			this.groupBoxHello.TabIndex = 1;
			this.groupBoxHello.TabStop = false;
			this.groupBoxHello.Text = "Credential Windows Hello";
			//
			// checkedListCredentials
			//
			this.checkedListCredentials.CheckOnClick = true;
			this.checkedListCredentials.HorizontalScrollbar = true;
			this.checkedListCredentials.IntegralHeight = false;
			this.checkedListCredentials.Location = new System.Drawing.Point(12, 22);
			this.checkedListCredentials.Name = "checkedListCredentials";
			this.checkedListCredentials.Size = new System.Drawing.Size(512, 150);
			this.checkedListCredentials.TabIndex = 0;
			this.checkedListCredentials.ItemCheck += new System.Windows.Forms.ItemCheckEventHandler(this.CredentialsItemCheck);
			//
			// labelHelloStatus
			//
			this.labelHelloStatus.Location = new System.Drawing.Point(12, 178);
			this.labelHelloStatus.Name = "labelHelloStatus";
			this.labelHelloStatus.Size = new System.Drawing.Size(512, 40);
			this.labelHelloStatus.TabIndex = 1;
			//
			// buttonDeleteChecked
			//
			this.buttonDeleteChecked.Location = new System.Drawing.Point(12, 224);
			this.buttonDeleteChecked.Name = "buttonDeleteChecked";
			this.buttonDeleteChecked.Size = new System.Drawing.Size(180, 26);
			this.buttonDeleteChecked.TabIndex = 2;
			this.buttonDeleteChecked.Text = "Удалить отмеченные";
			this.buttonDeleteChecked.UseVisualStyleBackColor = true;
			this.buttonDeleteChecked.Click += new System.EventHandler(this.DeleteCheckedButtonClick);
			//
			// buttonRefresh
			//
			this.buttonRefresh.Location = new System.Drawing.Point(198, 224);
			this.buttonRefresh.Name = "buttonRefresh";
			this.buttonRefresh.Size = new System.Drawing.Size(100, 26);
			this.buttonRefresh.TabIndex = 3;
			this.buttonRefresh.Text = "Обновить";
			this.buttonRefresh.UseVisualStyleBackColor = true;
			this.buttonRefresh.Click += new System.EventHandler(this.RefreshButtonClick);
			//
			// progressBar
			//
			this.progressBar.Location = new System.Drawing.Point(304, 226);
			this.progressBar.Name = "progressBar";
			this.progressBar.Size = new System.Drawing.Size(220, 22);
			this.progressBar.TabIndex = 4;
			this.progressBar.Visible = false;
			//
			// buttonDiagnostics
			//
			this.buttonDiagnostics.Location = new System.Drawing.Point(12, 340);
			this.buttonDiagnostics.Name = "buttonDiagnostics";
			this.buttonDiagnostics.Size = new System.Drawing.Size(180, 26);
			this.buttonDiagnostics.TabIndex = 2;
			this.buttonDiagnostics.Text = "🔍 Диагностика PRF";
			this.buttonDiagnostics.UseVisualStyleBackColor = true;
			this.buttonDiagnostics.Click += new System.EventHandler(this.DiagnosticsButtonClick);
			//
			// FIDO2OptionsForm
			//
			this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
			this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
			this.ClientSize = new System.Drawing.Size(560, 378);
			this.Controls.Add(this.buttonDiagnostics);
			this.Controls.Add(this.groupBoxHello);
			this.Controls.Add(this.textBoxTop);
			this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
			this.MaximizeBox = false;
			this.MinimizeBox = false;
			this.Name = "FIDO2OptionsForm";
			this.ShowIcon = false;
			this.ShowInTaskbar = false;
			this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
			this.Text = "KeePassFIDO2";
			this.groupBoxHello.ResumeLayout(false);
			this.ResumeLayout(false);
			this.PerformLayout();
		}

		private System.Windows.Forms.TextBox textBoxTop;
		private System.Windows.Forms.GroupBox groupBoxHello;
		private System.Windows.Forms.CheckedListBox checkedListCredentials;
		private System.Windows.Forms.Label labelHelloStatus;
		private System.Windows.Forms.Button buttonDeleteChecked;
		private System.Windows.Forms.Button buttonRefresh;
		private System.Windows.Forms.ProgressBar progressBar;
		private System.Windows.Forms.Button buttonDiagnostics;

		#endregion
	}
}
