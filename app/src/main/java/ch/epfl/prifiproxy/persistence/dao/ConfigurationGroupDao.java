package ch.epfl.prifiproxy.persistence.dao;

import android.arch.lifecycle.LiveData;
import android.arch.persistence.room.Dao;
import android.arch.persistence.room.Delete;
import android.arch.persistence.room.Insert;
import android.arch.persistence.room.OnConflictStrategy;
import android.arch.persistence.room.Query;
import android.arch.persistence.room.Update;

import java.util.List;

import ch.epfl.prifiproxy.persistence.entity.Configuration;
import ch.epfl.prifiproxy.persistence.entity.ConfigurationGroup;

@Dao
public interface ConfigurationGroupDao {
    @Query("SELECT * FROM ConfigurationGroup WHERE id = :id")
    LiveData<ConfigurationGroup> get(int id);

    @Query("SELECT * FROM ConfigurationGroup ORDER BY name ASC")
    LiveData<List<ConfigurationGroup>> getAll();

    @Query("SELECT * FROM ConfigurationGroup WHERE isActive = 1")
    ConfigurationGroup getActive();

    @Query("SELECT * FROM ConfigurationGroup WHERE isActive = 1")
    LiveData<ConfigurationGroup> getActiveLive();

    @Query("SELECT * FROM Configuration WHERE groupId = (SELECT id FROM ConfigurationGroup WHERE isActive = 1) ORDER BY priority")
    LiveData<List<Configuration>> getConfigurationsForActiveGroup();

    @Query("UPDATE Configuration SET isActive = 0 WHERE groupId = :groupId")
    void deactivateConfigurationForGroup(int groupId);

    @Query("UPDATE Configuration SET isActive = 1 WHERE groupId = :groupId AND priority = (SELECT MIN(priority) FROM Configuration WHERE groupId = :groupId)")
    void activateConfigurationForGroup(int groupId);

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    long[] insert(ConfigurationGroup... groups);

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    long[] insert(List<ConfigurationGroup> groups);

    @Update
    void update(ConfigurationGroup... groups);

    @Update
    void update(List<ConfigurationGroup> groups);

    @Delete
    void delete(ConfigurationGroup... groups);

    @Delete
    void delete(List<ConfigurationGroup> groups);

    @Query("DELETE FROM ConfigurationGroup")
    void deleteAll();
}