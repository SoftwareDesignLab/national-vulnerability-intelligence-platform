package edu.rit.se.nvip.cvepatches.utils.controllers;

import java.io.File;
import java.io.IOException;
import java.sql.SQLException;

import org.eclipse.jgit.api.errors.GitAPIException;

//import javafx.event.ActionEvent;
import edu.rit.se.nvip.cvepatches.JGitCVEPatchDownloader;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.ProgressIndicator;
import javafx.scene.control.TextField;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
//import javafx.scene.text.Text;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;

public class UploadController {

	// This is the parent stage
	private Stage dialogStage;

	// This is the Text box element in the view for name of bank
	@FXML
	private TextField repoPath;
	@FXML
	private TextField clonePath;
	@FXML
	private Label lblMessage;
	@FXML
	private TextField outputPath;
	@FXML
	private Button uploadRepo;
	@FXML
	private Button chooseClone;
	@FXML
	private Button chooseOutput;
	private File repoFile;
	@FXML
	private ProgressBar progressbar;
	@FXML
	private ProgressIndicator progressindicator;
	// Method to set the parent stage of the current view

	public void setDialogStage(Stage dialogStage) {
		this.dialogStage = dialogStage;
	}

	@FXML
	public File chooseRepo() {
		String path = "";
		FileChooser fileChooser = new FileChooser();
		FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("CSV files (*.csv)", "*.csv");
		fileChooser.getExtensionFilters().add(extFilter);
		File repoCsv = fileChooser.showOpenDialog(dialogStage);
		if (repoCsv != null) {
			path = repoCsv.getPath();
			this.repoPath.setText(path);
			this.repoFile = repoCsv;
		}
		return repoCsv;
	}

	@FXML
	public String chooseCloneFolder() {
		String path = "";
		DirectoryChooser directoryChooser = new DirectoryChooser();
		File selectedDirectory = directoryChooser.showDialog(dialogStage);

		if (selectedDirectory == null) {
			// No Directory selected
		} else {
			path = selectedDirectory.getAbsolutePath();
			this.clonePath.setText(path);

		}
		return path;
	}

	@FXML
	public String chooseOutputFolder() {
		String path = "";
		DirectoryChooser directoryChooser = new DirectoryChooser();
		File selectedDirectory = directoryChooser.showDialog(dialogStage);

		if (selectedDirectory == null) {
			// No Directory selected
		} else {
			path = selectedDirectory.getAbsolutePath();
			this.outputPath.setText(path);

		}
		return path;
	}

	@FXML
	public void start() {
		UploadController thiscontroller = this;
		Task task = new Task<Void>() {
			@Override
			public Void call() throws IOException, GitAPIException, SQLException {
				JGitCVEPatchDownloader.parse(repoFile, clonePath.getText());
				return null;
			}
		};
		new Thread(task).start();
	}

	private void close() {
		dialogStage.fireEvent(new WindowEvent(dialogStage, WindowEvent.WINDOW_CLOSE_REQUEST));
	}

	public void increaseProgress(float quant) {
		this.progressbar.setProgress(quant);
		this.progressindicator.setProgress(quant);
	}

}
