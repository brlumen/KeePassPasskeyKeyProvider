using System.ComponentModel;

namespace KeePassPasskeyKeyProvider
{
	partial class DeviceNameForm
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
			this.labelDeviceName = new System.Windows.Forms.Label();
			this.textBoxDeviceName = new System.Windows.Forms.TextBox();
			this.checkBoxKeepDevices = new System.Windows.Forms.CheckBox();
			this.labelKeepDevices = new System.Windows.Forms.Label();
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
			this.layout.RowCount = 6;
			this.layout.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.layout.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.layout.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.layout.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.layout.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.layout.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.layout.Controls.Add(this.labelDescription, 0, 0);
			this.layout.Controls.Add(this.labelDeviceName, 0, 1);
			this.layout.Controls.Add(this.textBoxDeviceName, 0, 2);
			this.layout.Controls.Add(this.checkBoxKeepDevices, 0, 3);
			this.layout.Controls.Add(this.labelKeepDevices, 0, 4);
			this.layout.Controls.Add(this.buttons, 0, 5);
			//
			// labelDescription
			//
			this.labelDescription.AutoSize = true;
			this.labelDescription.Margin = new System.Windows.Forms.Padding(3, 3, 3, 12);
			this.labelDescription.MaximumSize = new System.Drawing.Size(520, 0);
			this.labelDescription.Name = "labelDescription";
			//
			// labelDeviceName
			//
			this.labelDeviceName.AutoSize = true;
			this.labelDeviceName.Margin = new System.Windows.Forms.Padding(3, 3, 3, 3);
			this.labelDeviceName.Name = "labelDeviceName";
			this.labelDeviceName.Text = Strings.DeviceNameLabel;
			//
			// textBoxDeviceName
			//
			this.textBoxDeviceName.Dock = System.Windows.Forms.DockStyle.Fill;
			this.textBoxDeviceName.Margin = new System.Windows.Forms.Padding(3, 0, 3, 12);
			this.textBoxDeviceName.Name = "textBoxDeviceName";
			this.textBoxDeviceName.TabIndex = 0;
			//
			// checkBoxKeepDevices
			//
			this.checkBoxKeepDevices.AutoSize = true;
			this.checkBoxKeepDevices.Checked = true;
			this.checkBoxKeepDevices.Margin = new System.Windows.Forms.Padding(3, 0, 3, 3);
			this.checkBoxKeepDevices.Name = "checkBoxKeepDevices";
			this.checkBoxKeepDevices.TabIndex = 1;
			this.checkBoxKeepDevices.Text = Strings.KeepDevicesCheckBox;
			this.checkBoxKeepDevices.UseVisualStyleBackColor = true;
			//
			// labelKeepDevices
			//
			this.labelKeepDevices.AutoSize = true;
			this.labelKeepDevices.Margin = new System.Windows.Forms.Padding(20, 0, 3, 12);
			this.labelKeepDevices.MaximumSize = new System.Drawing.Size(500, 0);
			this.labelKeepDevices.Name = "labelKeepDevices";
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
			this.buttonCancel.TabIndex = 3;
			this.buttonCancel.Text = Strings.Cancel;
			this.buttonCancel.UseVisualStyleBackColor = true;
			//
			// buttonOK
			//
			this.buttonOK.DialogResult = System.Windows.Forms.DialogResult.OK;
			this.buttonOK.Name = "buttonOK";
			this.buttonOK.Size = new System.Drawing.Size(90, 25);
			this.buttonOK.TabIndex = 2;
			this.buttonOK.Text = Strings.Continue;
			this.buttonOK.UseVisualStyleBackColor = true;
			//
			// DeviceNameForm
			//
			this.AcceptButton = this.buttonOK;
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
			this.Name = "DeviceNameForm";
			this.ShowInTaskbar = false;
			this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
			this.Text = Strings.CreateCredentialTitle;
			this.layout.ResumeLayout(false);
			this.layout.PerformLayout();
			this.buttons.ResumeLayout(false);
			this.ResumeLayout(false);
			this.PerformLayout();
		}

		private System.Windows.Forms.TableLayoutPanel layout;
		private System.Windows.Forms.Label labelDescription;
		private System.Windows.Forms.Label labelDeviceName;
		private System.Windows.Forms.TextBox textBoxDeviceName;
		private System.Windows.Forms.CheckBox checkBoxKeepDevices;
		private System.Windows.Forms.Label labelKeepDevices;
		private System.Windows.Forms.FlowLayoutPanel buttons;
		private System.Windows.Forms.Button buttonCancel;
		private System.Windows.Forms.Button buttonOK;

		#endregion
	}
}
