
package codeproject;

import java.awt.Color;
import java.awt.Image;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.imageio.ImageIO;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

/**
 *
 * @author HP
 */
public class MainForm extends javax.swing.JFrame {

    String name,gender,birth,address,issueDate,expDate,idCard,pinCode;
    JavaSmartcard javaCard ;
    
    public MainForm() {
        initComponents();
        javaCard = new JavaSmartcard();
        this.getContentPane().setBackground(Color.white);
        //get date
        Calendar cal = Calendar.getInstance();
        int d = cal.get(Calendar.DAY_OF_MONTH);
        int m = cal.get(Calendar.MONTH)+1;
        int y = cal.get(Calendar.YEAR);
        String day = String.valueOf(d);
        if(day.length()<2) day = "0"+day;
        String month = String.valueOf(m);
        if(month.length()<2) month = "0"+month;
        String dayOfIssue = "";
        dayOfIssue = day+"/"+month+"/"+y;
        String dayOfExp = "";
        dayOfExp = day+"/"+month+"/"+(y+10);
        //set date
        txtIssueDate.setText(dayOfIssue);
        txtExpDate.setText(dayOfExp);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        group_gender = new javax.swing.ButtonGroup();
        btn_view = new javax.swing.JButton();
        connect_Button = new javax.swing.JButton();
        jSeparator1 = new javax.swing.JSeparator();
        status_Label = new javax.swing.JLabel();
        terminals_ComboBox = new javax.swing.JComboBox();
        btn_save = new javax.swing.JButton();
        refresh_Button = new javax.swing.JButton();
        btn_file = new javax.swing.JButton();
        lbl_image = new javax.swing.JLabel();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        jLabel7 = new javax.swing.JLabel();
        txt_name = new javax.swing.JTextField();
        txt_address = new javax.swing.JTextField();
        txt_id = new javax.swing.JTextField();
        btn_m = new javax.swing.JRadioButton();
        btn_f = new javax.swing.JRadioButton();
        cbb_dob = new javax.swing.JComboBox<>();
        cbb_mob = new javax.swing.JComboBox<>();
        txt_yob = new javax.swing.JTextField();
        txtExpDate = new javax.swing.JLabel();
        jLabel9 = new javax.swing.JLabel();
        txt_pin = new javax.swing.JTextField();
        txt_file_name = new javax.swing.JLabel();
        txtIssueDate = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Thẻ CDĐT");

        btn_view.setText("Test");
        btn_view.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_viewActionPerformed(evt);
            }
        });

        connect_Button.setText("Connect");
        connect_Button.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                connect_ButtonActionPerformed(evt);
            }
        });

        status_Label.setFont(new java.awt.Font("Tahoma", 2, 14)); // NOI18N

        terminals_ComboBox.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "--select--" }));
        terminals_ComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                terminals_ComboBoxActionPerformed(evt);
            }
        });

        btn_save.setText("Lưu");
        btn_save.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_saveActionPerformed(evt);
            }
        });

        refresh_Button.setText("Refresh");
        refresh_Button.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                refresh_ButtonActionPerformed(evt);
            }
        });

        btn_file.setText("Chọn ảnh");
        btn_file.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_fileActionPerformed(evt);
            }
        });

        lbl_image.setText("ảnh 2x3");
        lbl_image.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 0, 0)));

        jLabel1.setText("Họ và tên:");

        jLabel2.setText("Giới tính:");

        jLabel3.setText("Ngày sinh:");

        jLabel4.setText("Ngày cấp thẻ:");

        jLabel5.setText("Hạn sử dụng:");

        jLabel6.setText("Số thẻ:");

        jLabel7.setText("Địa chỉ:");

        group_gender.add(btn_m);
        btn_m.setSelected(true);
        btn_m.setText("Nam");
        btn_m.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_mActionPerformed(evt);
            }
        });

        group_gender.add(btn_f);
        btn_f.setText("Nữ");
        btn_f.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_fActionPerformed(evt);
            }
        });

        cbb_dob.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31" }));

        cbb_mob.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "12", "11", "10", "09", "08", "07", "06", "05", "04", "03", "02", "01" }));

        txtExpDate.setText("01/01/2030");

        jLabel9.setText("PIN:");

        txtIssueDate.setText("01/01/2020");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(39, 39, 39)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addComponent(jSeparator1, javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(layout.createSequentialGroup()
                                        .addGap(0, 0, Short.MAX_VALUE)
                                        .addComponent(btn_view, javax.swing.GroupLayout.PREFERRED_SIZE, 98, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addGap(18, 18, 18)
                                        .addComponent(btn_save, javax.swing.GroupLayout.PREFERRED_SIZE, 98, javax.swing.GroupLayout.PREFERRED_SIZE)))
                                .addGap(19, 19, 19))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(refresh_Button)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(terminals_ComboBox, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(connect_Button, javax.swing.GroupLayout.PREFERRED_SIZE, 87, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(status_Label, javax.swing.GroupLayout.PREFERRED_SIZE, 78, javax.swing.GroupLayout.PREFERRED_SIZE))))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(29, 29, 29)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(btn_file)
                            .addComponent(lbl_image, javax.swing.GroupLayout.PREFERRED_SIZE, 100, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(txt_file_name, javax.swing.GroupLayout.PREFERRED_SIZE, 87, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(29, 29, 29)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jLabel5)
                                    .addComponent(jLabel6)
                                    .addComponent(jLabel9))
                                .addGap(20, 20, 20)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(layout.createSequentialGroup()
                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                            .addComponent(txt_pin)
                                            .addComponent(txt_id))
                                        .addGap(3, 3, 3))
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(txtExpDate)
                                        .addGap(0, 0, Short.MAX_VALUE))))
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jLabel1)
                                    .addComponent(jLabel2)
                                    .addComponent(jLabel3)
                                    .addComponent(jLabel7)
                                    .addComponent(jLabel4))
                                .addGap(20, 20, 20)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(txt_name)
                                    .addComponent(txt_address)
                                    .addGroup(layout.createSequentialGroup()
                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                            .addGroup(layout.createSequentialGroup()
                                                .addComponent(btn_m)
                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                .addComponent(btn_f))
                                            .addGroup(layout.createSequentialGroup()
                                                .addComponent(cbb_dob, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                                .addComponent(cbb_mob, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addGap(18, 18, 18)
                                                .addComponent(txt_yob, javax.swing.GroupLayout.PREFERRED_SIZE, 94, javax.swing.GroupLayout.PREFERRED_SIZE))
                                            .addComponent(txtIssueDate))
                                        .addGap(0, 170, Short.MAX_VALUE)))))
                        .addGap(19, 19, 19)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(btn_save, javax.swing.GroupLayout.PREFERRED_SIZE, 46, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(btn_view, javax.swing.GroupLayout.PREFERRED_SIZE, 46, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(59, 59, 59)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(jLabel1)
                                    .addComponent(txt_name, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(18, 18, 18)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(jLabel2)
                                    .addComponent(btn_m)
                                    .addComponent(btn_f))
                                .addGap(18, 18, 18)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(jLabel3)
                                    .addComponent(cbb_dob, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(cbb_mob, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(txt_yob, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(18, 18, 18)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(jLabel7)
                                    .addComponent(txt_address, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(18, 18, 18)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(jLabel4)
                                    .addComponent(txtIssueDate))
                                .addGap(19, 19, 19)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(jLabel5)
                                    .addComponent(txtExpDate))
                                .addGap(29, 29, 29)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(jLabel6)
                                    .addComponent(txt_id, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(18, 18, 18)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(txt_pin, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(jLabel9)))
                            .addGroup(layout.createSequentialGroup()
                                .addGap(2, 2, 2)
                                .addComponent(lbl_image, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(26, 26, 26)
                                .addComponent(btn_file)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(txt_file_name, javax.swing.GroupLayout.PREFERRED_SIZE, 101, javax.swing.GroupLayout.PREFERRED_SIZE)))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 130, Short.MAX_VALUE)))
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 2, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(connect_Button, javax.swing.GroupLayout.PREFERRED_SIZE, 31, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(terminals_ComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(refresh_Button))
                    .addComponent(status_Label, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        getAccessibleContext().setAccessibleName("Smart Card Calculator");

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private byte[] getLCData(String byte1Str, String byte2Str) throws Exception
    {
        byte[] data_LC = new byte[2];
        byte byte1 =  Byte.parseByte(byte1Str );
        byte byte2 =  Byte.parseByte(byte2Str);
        data_LC[0] = byte1;
        data_LC[1] = byte2;
      
        return data_LC;
    }
    
    private boolean selectApplet(byte[] apdu)
    {
        boolean isSelected = false;
        try
        {
            javaCard.sendApdu(apdu);
            byte[] data = javaCard.getData();
            
            this.status_Label.setText(""+Integer.toHexString(javaCard.getStatusWords()).toUpperCase());
            
            isSelected = true;
        } 
        catch (CardException | IllegalArgumentException | NullPointerException ex) 
        {
            JOptionPane.showMessageDialog(this, "Error while tried to Select calculator applet\n"+ex.getMessage()+"", "APDU sending fail", JOptionPane.ERROR_MESSAGE);
            isSelected = false;
        }        
        
        return isSelected;
    }
    private void btn_viewActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_viewActionPerformed
        
        String command = "00A4040006112233445500";
        byte[] apdu = JavaSmartcard.hexStringToByteArray(command);
        if (!selectApplet(apdu))
        {
            return;
        }
        else{
            System.out.println("Select applet successfully");
        }
        List<Byte> imageBytes = new ArrayList<>();
        //ins 0x02
        command = "00020000";
        apdu = JavaSmartcard.hexStringToByteArray(command);
        try {
            javaCard.sendApdu(apdu);
        } catch (CardException ex) {
            Logger.getLogger(MainForm.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalArgumentException ex) {
            Logger.getLogger(MainForm.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NullPointerException ex) {
            Logger.getLogger(MainForm.class.getName()).log(Level.SEVERE, null, ex);
        }
        //ins 0x01
        command = "00010000";
        apdu = JavaSmartcard.hexStringToByteArray(command);
        //System.out.println(""+ JavaSmartcard.htos(apdu));
        for(int i = 0; i<200;i++){
            try
            {
                javaCard.sendApdu(apdu);
                byte[] data = javaCard.getData();
                for(int j =0;j<data.length;j++){
                    if(data[j]!=0x00){
                        imageBytes.add(data[j]);
                    }
                }
                
            } 
            catch (CardException | IllegalArgumentException ex) 
            {
                JOptionPane.showMessageDialog(this, "Error while tried to send command APDU\n"+ex.getMessage()+"", "APDU sending fail", JOptionPane.ERROR_MESSAGE);
            }
        }
        //Convert convert = new Convert();
        String base64String = Convert.hexToString(imageBytes);
        byte[] btDataFile;
        BufferedImage image = null;
        try {
            btDataFile = new sun.misc.BASE64Decoder().decodeBuffer(base64String);
            image = ImageIO.read(new ByteArrayInputStream(btDataFile));
        } catch (IOException ex) {
            Logger.getLogger(MainForm.class.getName()).log(Level.SEVERE, null, ex);
        }
         
        JOptionPane.showMessageDialog(null, "", "Image", 
        JOptionPane.INFORMATION_MESSAGE, 
        new ImageIcon(image));
    }//GEN-LAST:event_btn_viewActionPerformed

    private void connect_ButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_connect_ButtonActionPerformed
        
        if (this.terminals_ComboBox.getSelectedItem().equals( "--select--"))
        {
            return;
        }
        CardTerminal cardReader = javaCard.getCardReader((String)this.terminals_ComboBox.getSelectedItem());
        try 
        {
            javaCard.connectToCard(cardReader);
            this.status_Label.setText("Connected");
        }
        catch (CardException ex) 
        {
            JOptionPane.showMessageDialog(this, "Problems while tried to connect with the smart card.\n"+ex.getMessage(), "Card Error", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_connect_ButtonActionPerformed

    private void btn_saveActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_saveActionPerformed
        
        boolean checkInput = getInfo();
        
        //select applet
        String command = "00A4040006112233445500";
        byte[] apdu = JavaSmartcard.hexStringToByteArray(command);
        if (!selectApplet(apdu))
        {
            return;
        }
        else{
            System.out.println("Select applet successfully");
        }
        
        
        //send image
        
        File f = new File(txt_file_name.getText());
        try {
            
            String dataString = Convert.stringToHex(Convert.imageToBase64(f));
            byte[] dataArr = JavaSmartcard.hexStringToByteArray(dataString);
            int i =0;
            while(i<dataArr.length){
                byte[] data = new byte[99];
                for(int j = 0; j<99;j++){
                    if(i<dataArr.length){
                        data[j]= dataArr[i];
                        i++;
                    }
                    else{
                        data[j]=(byte)0x00;
                    } 
                }
                command = "0000000063";
                //String lc = convert.stringToHex(String.valueOf(data.length));
                //System.out.println(lc);
                //command.concat(lc);
                command = command.concat(JavaSmartcard.byteArrayToHexString(data));
                apdu = JavaSmartcard.hexStringToByteArray(command);
                System.out.println(""+JavaSmartcard.htos(apdu));
                javaCard.sendApdu(apdu);
            }
        } catch (CardException|IOException e) {
            e.printStackTrace();
        }
        //send info
        String dataInfo = getDataInfo();
 
        System.out.println(dataInfo);
        System.out.println(dataInfo.length());
        String lc = Integer.toHexString(dataInfo.length()/2);
        String p1 = Convert.stringToHex(gender);
        command = "0003"+p1+"00"+lc+dataInfo;
        apdu = JavaSmartcard.hexStringToByteArray(command);
        System.out.println(""+JavaSmartcard.htos(apdu));
        try {
            javaCard.sendApdu(apdu);
        } catch (CardException ex) {
            Logger.getLogger(MainForm.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalArgumentException ex) {
            Logger.getLogger(MainForm.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NullPointerException ex) {
            Logger.getLogger(MainForm.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }//GEN-LAST:event_btn_saveActionPerformed

    private void refresh_ButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_refresh_ButtonActionPerformed
        try {
            List<CardTerminal> terminals = javaCard.getTerminals();
                this.terminals_ComboBox.removeAllItems();                
                for (int i = 0; i < terminals.size(); i++) 
                {
                    this.terminals_ComboBox.addItem(terminals.get(i).getName());
                }            
        } catch (Exception ex) {
            
            JOptionPane.showMessageDialog(this, "Getting problems while tried to access terminal list\n"+ex.getMessage()+".\nReresh agin or restart", "Coudl not get Terminals", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_refresh_ButtonActionPerformed

    private void terminals_ComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_terminals_ComboBoxActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_terminals_ComboBoxActionPerformed

    private void btn_fileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_fileActionPerformed
        JFileChooser chooser = new JFileChooser();
        //chooser.setCurrentDirectory(new File(System.getProperty("file.separator")+ "Pictures"));
        chooser.showOpenDialog(null);
        File f = chooser.getSelectedFile();
        if (f!=null) {
            String fileName = f.getAbsolutePath();
            txt_file_name.setText(fileName);
            ImageIcon icon = new ImageIcon(fileName);
            Image image = icon.getImage().getScaledInstance(lbl_image.getWidth(), lbl_image.getHeight(), Image.SCALE_SMOOTH);
            lbl_image.setIcon(new ImageIcon(image));
        }
        
    }//GEN-LAST:event_btn_fileActionPerformed

    private void btn_mActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_mActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_btn_mActionPerformed

    private void btn_fActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_fActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_btn_fActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(MainForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(MainForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(MainForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(MainForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new MainForm().setVisible(true);
            }
        });
    }
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JRadioButton btn_f;
    private javax.swing.JButton btn_file;
    private javax.swing.JRadioButton btn_m;
    private javax.swing.JButton btn_save;
    private javax.swing.JButton btn_view;
    private javax.swing.JComboBox<String> cbb_dob;
    private javax.swing.JComboBox<String> cbb_mob;
    private javax.swing.JButton connect_Button;
    private javax.swing.ButtonGroup group_gender;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JLabel lbl_image;
    private javax.swing.JButton refresh_Button;
    private javax.swing.JLabel status_Label;
    private javax.swing.JComboBox terminals_ComboBox;
    private javax.swing.JLabel txtExpDate;
    private javax.swing.JLabel txtIssueDate;
    private javax.swing.JTextField txt_address;
    private javax.swing.JLabel txt_file_name;
    private javax.swing.JTextField txt_id;
    private javax.swing.JTextField txt_name;
    private javax.swing.JTextField txt_pin;
    private javax.swing.JTextField txt_yob;
    // End of variables declaration//GEN-END:variables

    private boolean getInfo() {
        //get name
        name = txt_name.getText().toString().toUpperCase().trim();
        if(name.equals("")){
            JOptionPane.showMessageDialog(null, "Tên không hợp lệ");
            return false;
        }
        //System.out.println(name);
        //get gender
        if(btn_m.isSelected())
            gender = "M";
        else
            gender = "F";
        
        //get birth
        birth = "";
        String dob = cbb_dob.getSelectedItem().toString()+"/";
        String mob = cbb_mob.getSelectedItem().toString()+"/";
        String yob = txt_yob.getText().trim();
        try {
            int year = Integer.parseInt(yob); 
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(null, "Năm sinh không hợp lệ");
            return false;
        }
        birth = birth.concat(dob).concat(mob).concat(yob);
        //get address
        address = txt_address.getText().trim();
        if(address.equals("")){
            JOptionPane.showMessageDialog(null, "Địa chỉ không hợp lệ");
            return false;
        }
        // get issue/exp date
        issueDate = txtIssueDate.getText();
        expDate = txtExpDate.getText();
        //id
        idCard = txt_id.getText().trim();
        if(idCard.equals("")){
            JOptionPane.showMessageDialog(null, "Số thẻ không hợp lệ");
            return false;
        }
        return true;
    }

    private String getDataInfo() {
        String s = "";
        
        s = s.concat(returnS(name));
        s = s.concat(returnS(birth));
        s = s.concat(returnS(address));
        s = s.concat(returnS(issueDate));
        s = s.concat(returnS(expDate));
        s = s.concat(returnS(idCard));
        
        return s;
    }

    private String returnS(String string) {
        String t = "";
        String lc ="";
        t = Convert.stringToHex(string);
        lc = Integer.toHexString(string.length());
        if (lc.length()==1){
            lc = "0"+lc;
        }
        return lc+t;
    }
}
